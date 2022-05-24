
use std::convert::TryFrom;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::collections::{ LookupMap, LookupSet, UnorderedMap };
use near_sdk::{utils, env, near_bindgen, ext_contract, callback, Promise, AccountId, Balance, BorshStorageKey};
use near_sdk::json_types::{U128, U64};
use sha2::Sha512;
use sha2::Digest;
use ed25519_dalek::Verifier;
use serde_json::json;

mod internal;
mod manage;
mod tests;

near_sdk::setup_alloc!();

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Service {
    Stackoverflow,
    Twitter,
    Telegram,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct ServiceId {
    pub service: Service,
    pub id: ExternalId,
}

type ExternalId = AccountId;
type TokenId = AccountId;
type AccountTokenId = (AccountId, TokenId);
type ServiceTokenId = (ServiceId, TokenId);
type ServiceBatch = UnorderedMap<Service, ExternalId>;

const NEAR: &str = "near";
const PRICE_PER_BYTE: u128 = 10000000000000000000; // 19eyoctoNEAR
const NEW_DEPOSIT_PRICE: u128 = 20 * PRICE_PER_BYTE; // Not preciesed amount
const NEW_LINK_PRICE: u128 = 25 * PRICE_PER_BYTE; // Not preciesed amount
pub const CALLBACK_GAS: u64 = 20000000000000;

#[derive(BorshStorageKey, BorshSerialize)]
pub enum StorageKeys {
    Deposits,
    Tips,
    LinkedAccounts,
    Validators,
    WhitelistedTokens,
    SubLinkedAccounts { account_hash: Vec<u8> },
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
struct ValidatorMsg {
    service_id: ServiceId,
    account_id: AccountId,
    deadline: u64,
}


#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct NearTips {
    /// Master account for ownership methods (beta)
    horseradish_key: AccountId,
    deposits: LookupMap<AccountTokenId, Balance>,
    tips: LookupMap<ServiceTokenId, Balance>,
    linked_accounts: LookupMap<AccountId, ServiceBatch>,
    
    validators: UnorderedMap<String, Vec<u8>>,
    /// Is not using yet
    whitelisted_tokens: LookupSet<TokenId>,
}

impl Default for NearTips {
    fn default() -> Self {
        Self {
            horseradish_key: env::predecessor_account_id(),
            deposits: LookupMap::new(StorageKeys::Deposits),
            tips: LookupMap::new(StorageKeys::Tips),
            linked_accounts: LookupMap::new(StorageKeys::LinkedAccounts),
            validators: UnorderedMap::new(StorageKeys::Validators),
            whitelisted_tokens: LookupSet::new(StorageKeys::WhitelistedTokens),
        }
    }
}

#[ext_contract(ext_self)]
pub trait ExtSelf {
    fn withdraw_result_callback(#[callback] account_id: AccountId, withdraw_back: U128);
}

#[near_bindgen]
impl NearTips {

    pub fn get_deposit_account_id(&self, account_id: AccountId) -> u128 {
        match self.deposits.get(&(account_id, NEAR.to_string())) {
            Some(deposit) => deposit,
            None => 0
        }
    }

    #[payable]
    /// Method accepts near as deposit, that could be used for tips
    pub fn deposit_account(&mut self) {
        let deposit = self.deposit().1;
        if deposit == 0 {
            near_sdk::env::panic("Method should accept deposit.".as_bytes());
        }
    }

    #[payable]
    /// Method send tips to list of service accounts 
    /// The method also accepts deposit.
    /// user_ids - list of post authors (some post could have several authors)
    /// tips - amount of tips
    pub fn send_tips(&mut self, user_ids: Vec<ServiceId>, tips: U128) {
        let tips = tips.0;
        let (account_id, dep) = self.deposit();
        println!("Attached dep:{}", dep);
        let tips_per_user = tips / user_ids.len() as u128;
        if tips_per_user == 0 {
            near_sdk::env::panic("Too small deposit".as_bytes());
        }

        // Strange math connected with storage handling
        // Not sure is it ok
        // Required to have enough NEAR on contract balance for storage
        let mut storage_expances = 0;
        for service_id in user_ids {
            let service_token_id = &(service_id, NEAR.to_string());
            let collected_tips = match self.tips.get(service_token_id) {
                Some(stored_tips) => stored_tips + tips_per_user,
                None => {
                    storage_expances += NEW_DEPOSIT_PRICE;
                    tips_per_user
                }
            };
            self.tips.insert(service_token_id, &collected_tips);
        }
        self.decrease_deposit(&(account_id, NEAR.to_string()), tips + storage_expances);
    }

    #[private]
    pub fn withdraw_result_callback(&mut self, #[callback] account_id: AccountId, #[callback] withdraw_amount: U128) {
        println!("CALLBACKED!!!");
        if !utils::is_promise_success() {
            self.increase_deposit(&(account_id, NEAR.to_string()), withdraw_amount.0);
        }
    }

    /// Allows to withdraw deposited amount
    pub fn withdraw_deposit(&mut self, withdraw_amount: U128) {
        let withdraw_amount = withdraw_amount.0;
        let account_id = env::predecessor_account_id();
        self.decrease_deposit(&(account_id, NEAR.to_string()), withdraw_amount);
        Promise::new(account_id).transfer(withdraw_amount).then(
            ext_contract::withdraw_result_callback(
                account_id,
                withdraw_amount,
                &env::current_account_id(),
                0,
                CALLBACK_GAS
            )
        );
    }

    /// Get list of service accounts connected to near account
    /// root.near: [Stackoverflow, id], [Twitter, id]..
    pub fn get_linked_accounts(&self, account_id: AccountId) -> Vec<ServiceId> {
        let accounts = self.linked_accounts.get(&account_id);
        if accounts.is_none() {
            return vec![];
        }
        let accounts = accounts.unwrap();
        accounts.iter().map(|(service, id)| ServiceId{service, id}).collect()
    }

    /// Get amount of tips for some service account (ex. stackoverflow)
    pub fn get_service_id_tips(&self, service_id: ServiceId) -> u128 {
        match self.tips.get(&(service_id, NEAR.to_string())) {
            Some(tips) => tips,
            None => 0
        }
    }

    /// Iterates over all of service accounts connected to near account
    /// And sums all of tips
    pub fn get_account_id_tips(&self, account_id: AccountId) -> u128 {
        if let Some(ids) = self.linked_accounts.get(&account_id) {
            return ids.iter().map(|(service, id)| self.get_service_id_tips(ServiceId{service, id})).sum::<u128>();
        };
        0
    }

    /// Allows near account to collect tips from all of the linked service accounts
    pub fn withdraw_tips(&mut self) {
        let account_id = env::predecessor_account_id();
        self.withdraw_tips_to_account(&account_id);
    }

    #[payable]
    /// Takes validators signatures to prove that the owner of the near account is also owner of the service account.
    /// After the validation saves the link to storage
    /// And withdraws all collected tips to near account
    pub fn link_account(&mut self, service_id: ServiceId, account_id: AccountId, deadline: U64, signatures: Vec<Vec<u8>>, validators_pks: Vec<AccountId>) {
        let deadline = deadline.0;
        self.validate_signatures(&service_id, &account_id, deadline, signatures, validators_pks);
        let mut links_map = self.linked_accounts.get(&account_id).unwrap_or_else(|| {
            let new_map = UnorderedMap::new(
                StorageKeys::SubLinkedAccounts { account_hash: env::sha256(account_id.as_bytes()) }
            );
            self.linked_accounts.insert(&account_id, &new_map);
            new_map
        });
        links_map.insert(&service_id.service, &service_id.id);
        self.linked_accounts.insert(&account_id, &links_map);
        
        // Immidiatly send collected tips to new account
        self.withdraw_tips_to_account_with_commission(&service_id, &account_id, 1, true);
    }

    #[payable]
    /// Takes validators signatures to prove that the owner of the near account is also owner of the service account.
    /// And withdraws all collected tips to near account
    /// This functions takes 5% commision, and executes not by near account owner
    /// It is comfortable for the new NEAR users, that do not have any NEAR
    /// Because the bot could make this tx on near side.
    pub fn withdraw_tips_to(&mut self, service_id: ServiceId, account_id: AccountId, deadline: U64, signatures: Vec<Vec<u8>>, validators_pks: Vec<AccountId>) {
        let deadline = deadline.0;
        self.validate_signatures(&service_id, &account_id, deadline, signatures, validators_pks);
        self.withdraw_tips_to_account_with_commission(&service_id, &account_id, 5, false);
    }
}

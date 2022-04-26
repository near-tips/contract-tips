
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::collections::{ LookupMap, LookupSet, UnorderedMap };
use near_sdk::{env, near_bindgen, Promise, AccountId, Balance, BorshStorageKey};
use near_sdk::json_types::U128;
use sha2::Sha512;
use sha2::Digest;

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

#[derive(BorshStorageKey, BorshSerialize)]
pub enum StorageKeys {
    Deposits,
    Tips,
    LinkedAccounts,
    Validators,
    WhitelistedTokens,
    SubLinkedAccounts { account_hash: Vec<u8> },
}


#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct NearTips {
    horseradish_key: AccountId,
    deposits: LookupMap<AccountTokenId, Balance>,
    tips: LookupMap<ServiceTokenId, Balance>,
    linked_accounts: LookupMap<AccountId, ServiceBatch>,
    validators: UnorderedMap<String, Vec<u8>>,
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

#[near_bindgen]
impl NearTips {

    pub(crate) fn only_horseradish(&self) {
        assert_eq!(env::predecessor_account_id(), self.horseradish_key, "You are not a horseradish to call this method.")
    }

    pub fn add_validator(&mut self, validator_pk: String) {
        self.only_horseradish();
        let key_as_bytes = 
            &bs58::decode(
                validator_pk.clone(),
            )
            .into_vec()
            .unwrap();
        self.validators.insert(&validator_pk, &key_as_bytes);
    }

    pub fn remove_validator(&mut self, validator_pk: String) {
        self.only_horseradish();
        self.validators.remove(&validator_pk);
    }

    pub fn get_validators(&self) -> Vec<String> {
        self.validators.keys().collect()
    }

    pub fn get_deposit_account_id(&self, account_id: AccountId) -> u128 {
        match self.deposits.get(&(account_id, NEAR.to_string())) {
            Some(deposit) => deposit,
            None => 0
        }
    }

    pub(crate) fn set_tips(&mut self, service_token_id: &ServiceTokenId, set_tips: u128) {
        println!("ENTER SET TIP");
        println!("ServiceTokenId: {:?}", service_token_id);
        let res = self.tips.insert(service_token_id, &set_tips);
        println!("RES: {:?}", res);
    }

    pub(crate) fn decrease_deposit(&mut self, account_token_id: &AccountTokenId, amount: u128) {
        let deposit = match self.deposits.get(account_token_id) {
            Some(deposit) => deposit,
            None => 0
        };
        println!("Dep: {}, Am: {}", &deposit, &amount);
        self.deposits.insert(account_token_id, &(deposit - amount));
    }

    pub(crate) fn increase_deposit(&mut self, account_token_id: &AccountTokenId, amount: u128) -> u128 {
        let set_amount = match self.deposits.get(account_token_id) {
            Some(deposit) => deposit + amount,
            None => {
                if amount < NEW_DEPOSIT_PRICE {
                    near_sdk::env::panic("Not enough deposit for storage.".as_bytes())
                }
                amount - NEW_DEPOSIT_PRICE 
            }
        };
        self.deposits.insert(account_token_id, &set_amount);
        set_amount
    }

    pub(crate) fn deposit(&mut self) -> (AccountId, u128) {
        let account_id = env::predecessor_account_id();
        let attached_deposit = near_sdk::env::attached_deposit();
        if attached_deposit > 0 {
            self.increase_deposit(&(account_id.clone(), NEAR.to_string()), attached_deposit);
        }
        
        (account_id, attached_deposit)
    }

    pub(crate) fn validate_signatures(&mut self, service_id: &ServiceId, access_token_hash: Vec<u8>, account_id: &AccountId, deadline: u64, signatures: Vec<Vec<u8>>, validators_pks: Vec<AccountId>) {
        if signatures.len() != validators_pks.len() { near_sdk::env::panic("Wrong pks/signatures len.".as_bytes()) }
        if (signatures.len() as u64) < self.validators.len() * 2 / 3 || signatures.len() == 0 { near_sdk::env::panic("Not enough validators approve.".as_bytes()) }
        if deadline < near_sdk::env::block_timestamp() { near_sdk::env::panic("Deadline is missed.".as_bytes()) }

        let mut hasher = Sha512::new();
        hasher.update(&access_token_hash);
        hasher.update(service_id.try_to_vec().unwrap());
        hasher.update(account_id.as_bytes());
        hasher.update(deadline.to_be_bytes());

        let mut used_validators = Vec::new();
        for it in signatures.iter().zip(validators_pks.iter()) {
            let (signature, pk) = it;
            let signature = ed25519_dalek::Signature::try_from(signature.as_ref()).expect("Signature should be a valid array of 64 bytes [13, 254, 123, ...]");
            let trusted_key = ed25519_dalek::PublicKey::from_bytes(&self.validators.get(&pk).expect("The validator is not valid/existed.")).unwrap();
            if used_validators.contains(&pk) {
                near_sdk::env::panic("The validator's signature already verified.".as_bytes())
            }
            used_validators.push(pk);

            if trusted_key.verify_prehashed(hasher.clone(), None, &signature).is_err() {
                near_sdk::env::panic("Wrong signature for provided content.".as_bytes());
            }
        }
    }

    pub(crate) fn withdraw_tips_to_account(&mut self, account_id: &AccountId) {
        println!("Withdraw account: {}", account_id);
        if let Some(ids) = self.linked_accounts.get(&account_id) {
            let mut collected_tips = 0;
            for (service, id) in ids.iter() {
                let sid = ServiceId{service, id};
                collected_tips += self.get_service_id_tips(sid.clone());
                println!("Got some with accounts");
                self.set_tips(&(sid, NEAR.to_string()), 0);
                println!("Tips set");
            }
            let commission_amount = collected_tips * 10 / 1000;
            let withdraw_amount = collected_tips * 990 / 1000;
            Promise::new(account_id.to_string()).transfer(withdraw_amount);
        } else {
            near_sdk::env::panic("No linked accounts found.".as_bytes());
        }
    }

    pub(crate) fn withdraw_tips_to_account_with_commission(&mut self, service_id: &ServiceId, account_id: &AccountId, commission: u128) {
        let tip_amount = self.get_service_id_tips(service_id.clone());
        let withdraw_amount: u128 = tip_amount * (100 - commission) / 100;
        let commission_amount: u128 = tip_amount * (commission) / 100;
        self.set_tips(&(service_id.clone(), NEAR.to_string()), 0);
        self.increase_deposit(&(self.horseradish_key.clone(), NEAR.to_string()), commission_amount);
        Promise::new(account_id.to_string()).transfer(withdraw_amount);
    }

    #[payable]
    pub fn deposit_account(&mut self) {
        let deposit = self.deposit().1;
        if deposit == 0 {
            near_sdk::env::panic("Method should accept deposit.".as_bytes());
        }
    }

    #[payable]
    pub fn send_tips(&mut self, user_ids: Vec<ServiceId>, tips: U128) {
        let tips = tips.0;
        let (account_id, dep) = self.deposit();
        println!("Attached dep:{}", dep);
        let tips_per_user = tips / user_ids.len() as u128;
        if tips_per_user == 0 {
            near_sdk::env::panic("Too small deposit".as_bytes());
        }

        // Strange math connected with storage handling
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

    pub fn withdraw_deposit(&mut self, withdraw_amount: U128) {
        let withdraw_amount = withdraw_amount.0;
        let account_id = env::predecessor_account_id();
        self.decrease_deposit(&(account_id.clone(), NEAR.to_string()), withdraw_amount);
        Promise::new(account_id).transfer(withdraw_amount);
    }

    pub fn get_linked_accounts(&self, account_id: AccountId) -> Vec<ServiceId> {
        let accounts = self.linked_accounts.get(&account_id);
        if accounts.is_none() {
            return vec![];
        }
        let accounts = accounts.unwrap();
        accounts.iter().map(|(service, id)| ServiceId{service, id}).collect()
    }

    pub fn get_service_id_tips(&self, service_id: ServiceId) -> u128 {
        match self.tips.get(&(service_id, NEAR.to_string())) {
            Some(tips) => tips,
            None => 0
        }
    }

    pub fn get_account_id_tips(&self, account_id: AccountId) -> u128 {
        if let Some(ids) = self.linked_accounts.get(&account_id) {
            return ids.iter().map(|(service, id)| self.get_service_id_tips(ServiceId{service, id})).sum::<u128>();
        }
        0
    }

    pub fn withdraw_tips(&mut self) {
        let account_id = env::predecessor_account_id();
        self.withdraw_tips_to_account(&account_id);
    }

    #[payable]
    pub fn link_account(&mut self, service_id: ServiceId, access_token_hash: Vec<u8>, account_id: AccountId, deadline: u64, signatures: Vec<Vec<u8>>, validators_pks: Vec<AccountId>) {
        self.validate_signatures(&service_id, access_token_hash, &account_id, deadline, signatures, validators_pks);
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
        self.withdraw_tips_to_account_with_commission(&service_id, &account_id, 1);
    }

    #[payable]
    pub fn withdraw_tips_to(&mut self, service_id: ServiceId, access_token_hash: Vec<u8>, account_id: AccountId, deadline: u64, signatures: Vec<Vec<u8>>, validators_pks: Vec<AccountId>) {
        self.validate_signatures(&service_id, access_token_hash, &account_id, deadline, signatures, validators_pks);
        self.withdraw_tips_to_account_with_commission(&service_id, &account_id, 5);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    extern crate rand;
    use super::*;
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};
    use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signature};
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;
    use std::convert::TryInto;

    struct ContextHandler {
        context: VMContext
    }

    impl ContextHandler {
        fn new() -> Self {
            Self {
                context: get_context(vec![], false)
            }
        }

        fn setup_context(&mut self, attached_deposit: Option<u128>, predecessor_account_id: Option<String>) {
            if let Some(attached_deposit) = attached_deposit {
                self.context.attached_deposit = attached_deposit;
            }
            if let Some(predecessor_account_id) = predecessor_account_id {
                self.context.predecessor_account_id = predecessor_account_id.clone();
                self.context.signer_account_id = predecessor_account_id;
            }
            testing_env!(self.context.clone());
        }
    }

    fn get_context(input: Vec<u8>, is_view: bool) -> VMContext {
        VMContext {
            current_account_id: "alice_near".to_string(),
            signer_account_id: "carol_near".to_string(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id: "carol_near".to_string(),
            input,
            block_index: 0,
            block_timestamp: 0,
            account_balance: 0,
            account_locked_balance: 0,
            storage_usage: 0,
            attached_deposit: 0,
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

    #[test]
    fn add_validator() {
        let mut context_handler = ContextHandler::new();
        context_handler.setup_context(None, None);
        let mut contract = NearTips::default();

        let mut csprng = OsRng{};
        let validatork_kp = Keypair::generate(&mut csprng);
        let val_pk = bs58::encode(validatork_kp.public.as_bytes()).into_string();
        contract.add_validator(val_pk.clone());
        let mut validators = contract.get_validators();
        assert_eq!(validators.len(), 1, "Wrong validators length.");
        assert_eq!(validators.pop(), Some(val_pk), "Wrong validator key.");
    }

    #[test]
    #[should_panic(
        expected = "You are not a horseradish to call this method."
    )]
    fn add_validator_only_horseredish() {
        // Initialize contract
        let mut context_handler = ContextHandler::new();
        context_handler.setup_context(None, None);
        let mut contract = NearTips::default();

        let mut context = get_context(vec![], false);
        context.predecessor_account_id = "alice_near".to_string();
        testing_env!(context);

        let mut csprng = OsRng{};
        let validatork_kp = Keypair::generate(&mut csprng);
        let val_pk = bs58::encode(validatork_kp.public.as_bytes()).into_string();
        contract.add_validator(val_pk.clone());
    }

    #[test]
    fn get_default_tips() {
        let mut context_handler = ContextHandler::new();
        context_handler.setup_context(None, None);
        let contract = NearTips::default();
        assert_eq!(
            0,
            contract.get_account_id_tips("alice_near".to_string())
        );
    }

    #[test]
    fn get_default_deposit() {
        let mut context_handler = ContextHandler::new();
        context_handler.setup_context(None, None);
        let contract = NearTips::default();
        assert_eq!(
            0,
            contract.get_deposit_account_id("alice_near".to_string())
        );
    }

    #[test]
    fn initialize_deposit() {
        let deposit_amount = 3;
        let mut context_handler = ContextHandler::new();
        context_handler.setup_context(Some(deposit_amount + NEW_DEPOSIT_PRICE), None);

        let mut contract = NearTips::default();
        contract.deposit_account();
        assert_eq!(
            deposit_amount,
            contract.get_deposit_account_id("carol_near".to_string())
        );
    }

    #[test]
    fn send_tip_from_deposit() {
        let deposit_amount = 3;
        let tip_amount = 6;
        let mut context_handler = ContextHandler::new();
        context_handler.setup_context(Some(deposit_amount + NEW_DEPOSIT_PRICE), None);
        let mut contract = NearTips::default();

        // Make deposit
        contract.deposit_account();
        // Send tips
        contract.send_tips(vec![ServiceId{service: Service::Stackoverflow, id: '1'.to_string()}], U128(tip_amount));
        assert_eq!(
            tip_amount,
            contract.get_service_id_tips(ServiceId{service: Service::Stackoverflow, id: '1'.to_string()})
        );
    }

    #[test]
    fn send_tips_to_several_accounts() {
        let deposit_amount = 6;
        let tip_amount = 3;
        let mut context_handler = ContextHandler::new();
        context_handler.setup_context(Some(deposit_amount + 2 * NEW_DEPOSIT_PRICE), None);
        let mut contract = NearTips::default();
        // Make deposit
        contract.deposit_account();
        // Send tips
        contract.send_tips(vec![ServiceId{service: Service::Stackoverflow, id: '1'.to_string()},
                                ServiceId{service: Service::Stackoverflow, id: '2'.to_string()}], U128(6));
        
        assert_eq!(
            tip_amount,
            contract.get_service_id_tips(ServiceId{service: Service::Stackoverflow, id: '1'.to_string()})
        );
        assert_eq!(
            tip_amount,
            contract.get_service_id_tips(ServiceId{service: Service::Stackoverflow, id: '2'.to_string()})
        );
    }

    #[test]
    fn link_account() {
        let tip_amount = 100000000;
        let mut context = get_context(vec![], false);
        context.attached_deposit = tip_amount + NEW_LINK_PRICE;
        testing_env!(context.clone());
        // context_handler.setup_context(Some(tip_amount + NEW_LINK_PRICE), None);
        let mut contract = NearTips::default();

        // Hot start for horseredis deposit account
        contract.deposit_account();

        let mut csprng = OsRng{};
        let validatork_kp = Keypair::generate(&mut csprng);
        let val_pk = bs58::encode(validatork_kp.public.as_bytes()).into_string();
        contract.add_validator(val_pk.clone());

        let mut hasher = Sha512::new();

        let access_key = "access_key";
        let access_key_hash = Sha512::digest(access_key.as_bytes());
        let account_id = "carol_near";
        let service_id = ServiceId{ service: Service::Stackoverflow, id: '1'.to_string() };
        let deadline: u64 = 1644359955;//{
        //     let start = SystemTime::now();
        //     start
        //     .duration_since(UNIX_EPOCH)
        //     .expect("Time went backwards").as_secs() + 10000
        // };
        hasher.update(&access_key_hash);
        hasher.update(&service_id.try_to_vec().unwrap());
        hasher.update(&account_id.as_bytes());
        hasher.update(deadline.to_be_bytes());

        let msg: Vec<u8> = [&access_key_hash, &service_id.try_to_vec().unwrap()[..], &account_id.as_bytes(), &deadline.clone().to_be_bytes()].concat();

        println!("msg: {:?}", &msg);

        println!("access key: {:?}", &access_key_hash);
        println!("service_id: {:?}", &service_id.try_to_vec().unwrap());
        println!("account_id: {}", &account_id);
        println!("deadline: {}", &deadline);
        let ch = hasher.clone();
        println!("hash: {:?}", &ch.finalize());

        println!("{} - {:?}",deadline.clone(), deadline.to_be_bytes());
        let signature = validatork_kp.sign_prehashed(hasher, None).unwrap();

        contract.link_account(service_id.clone(), access_key_hash.to_vec(), account_id.to_string(), deadline, vec![signature.to_bytes().to_vec()], vec![val_pk]);
        let accs = contract.get_linked_accounts(account_id.to_string());
        assert_eq!(
            accs.len(),
            1
        );

        // Send tips
        
        contract.send_tips(vec![service_id], U128(tip_amount as u128));
        // println!("Context predecessor_account_id: {}", &context.predecessor_account_id);
        // println!("Set account id: {}", &account_id);
        // context.predecessor_account_id = account_id.to_string();
        // testing_env!(context.clone());
        contract.withdraw_tips();
    }

    #[test]
    fn withdraw_tips_to() {
        let tip_amount = 100000000;
        let mut context = get_context(vec![], false);
        context.attached_deposit = tip_amount + NEW_DEPOSIT_PRICE * 2;
        testing_env!(context.clone());
        // context_handler.setup_context(Some(tip_amount + NEW_LINK_PRICE), None);
        let mut contract = NearTips::default();

        let mut csprng = OsRng{};
        let validatork_kp = Keypair::generate(&mut csprng);
        let val_pk = bs58::encode(validatork_kp.public.as_bytes()).into_string();
        contract.add_validator(val_pk.clone());

        let mut hasher = Sha512::new();

        let access_key = "4U9BG7i8*dhMsKThlPn7MA))";
        let access_key_hash = Sha512::digest(access_key.as_bytes());
        let account_id = "receiver_near";
        let service_id = ServiceId{ service: Service::Stackoverflow, id: '1'.to_string() };
        let deadline: u64 = 1644359955;

        hasher.update(&access_key_hash);
        hasher.update(&service_id.try_to_vec().unwrap());
        hasher.update(&account_id.as_bytes());
        hasher.update(deadline.to_be_bytes());
        let msg: Vec<u8> = [&access_key_hash, &service_id.try_to_vec().unwrap()[..], &account_id.as_bytes(), &deadline.clone().to_be_bytes()].concat();

        println!("msg: {:?}", &msg);
        println!("access key hash: {:?}", &access_key_hash);
        println!("service_id: {:?}", &service_id.try_to_vec().unwrap());
        println!("account_id: {}", &account_id);
        println!("deadline: {}", &deadline);
        let ch = hasher.clone();
        println!("hash: {:?}", &ch.finalize());

        println!("{} - {:?}",deadline.clone(), deadline.to_be_bytes());
        let signature = validatork_kp.sign_prehashed(hasher, None).unwrap();

        // Send tips
        contract.send_tips(vec![service_id.clone()], U128(tip_amount as u128));
        // println!("Context predecessor_account_id: {}", &context.predecessor_account_id);
        // println!("Set account id: {}", &account_id);
        // context.predecessor_account_id = account_id.to_string();
        // testing_env!(context.clone());
        // contract.withdraw_tips_to(service_id.clone(), access_key_hash.to_vec(), account_id.to_string(), deadline, vec![signature.to_bytes().to_vec()], vec![val_pk]);

    }

    #[test]
    fn test_signature() {
        let val_pk = PublicKey::from_bytes(&bs58::decode("BhyJvg3J4X9zBNp8WteiSWmBMGdezhFnuLRnGjx5j9zU".to_string()).into_vec().unwrap()).unwrap();
        let msg: Vec<u8> = [97, 99, 99, 101, 115, 115, 95, 107, 101, 121, 95, 104, 97, 115, 104, 0, 1, 0, 0, 0, 49, 98, 111, 98, 95, 110, 101, 97, 114, 0, 0, 0, 0, 98, 2, 241, 19].to_vec();
        let sign_bt = hex::decode("ed5c4b7dc58d8914ed2e3c2f71d018253606d52eb0b2674c2c93d3d6b50a98b4e94520277e9f86da09d6e3676e76852131fd8be25b0f5be95d9254c7ec6dad0e").expect("Decoding failed");
        println!("Sig verify: {:?}", val_pk.verify_strict(&msg, &Signature::new(sign_bt.try_into().unwrap())));
    }
    #[test]
    fn test_fe_borsh_serialization() {
        let hex = "00080000003137363934343035";
        let bts = hex::decode(hex).expect("Decoding failed");
        let service_id = ServiceId::try_from_slice(&bts).unwrap();
        assert_eq!(Service::Stackoverflow == service_id.service, true);
        assert_eq!("17694405".to_string(), service_id.id);        
    }

    #[test]
    fn test_2_hash() {
        let mut hasher = Sha512::new();
        let access_token = "3HAZM0ejGmzYWJpky32DQQ))";
        hasher.update(&access_token.as_bytes());
        let access_token_hash = hasher.finalize_reset();
        hasher.update(&access_token_hash);
        let access_token_2hash = hasher.finalize_reset();
        println!("AT: {}", &access_token);
        println!("ATH: {}", hex::encode(&access_token_hash));
        println!("AT2H: {:?}", hex::encode(&access_token_2hash));

        let account_id = "verkhohliad.testnet";
        hasher.update(&account_id.as_bytes());
        hasher.update(&access_token_hash);
        println!("Account id bytes: {}", hex::encode(&account_id.as_bytes()));
        println!("Extended hash: {}", hex::encode(hasher.finalize_reset()));

        let hand_mande_concat = "7665726b686f686c6961642e746573746e657458b4ae35c648b1e13e8e4f2e11743afc5ef1ca8f1dba01ff8b616b11d39d5a020b04b840dd1521b13f0fedbf9076d82b1c72afdd68e5af1a06a5d19402126f5f";
        hasher.update(hex::decode(&hand_mande_concat).expect("Decode failed"));
        println!("Hash of HM Concat: {}", hex::encode(hasher.finalize_reset()));

        let vectorized_concat = [account_id.as_bytes(), &access_token_hash].concat();
        println!("Vect concat: {}", hex::encode(&vectorized_concat));
        hasher.update(&vectorized_concat);
        println!("This concat: {}", hex::encode(hasher.finalize_reset()));
        println!("Concated bytes: {:?}", hex::decode(&hand_mande_concat).expect("fail"));

    }
}

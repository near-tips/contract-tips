
use std::convert::TryFrom;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::{ LookupMap };
use near_sdk::{near_bindgen, Promise};
use ed25519_dalek::{ Verifier };
use sha2::Sha512;
use sha2::Digest;

near_sdk::setup_alloc!();

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct TipsStack {
    tips: LookupMap<String, u128>,
    commitments: LookupMap<Vec<u8>, bool>,
    validators: LookupMap<String, bool>,
}

impl Default for TipsStack {
    fn default() -> Self {
        Self {
            tips: LookupMap::new(b"t".to_vec()),
            commitments: LookupMap::new(b"c".to_vec()),
            validators: LookupMap::new(b"v".to_vec()),
        }
    }
}

#[near_bindgen]
impl TipsStack {

    #[payable]
    pub fn make_tip(&mut self, nicknames: Vec<String>) {
        let attached_deposit = near_sdk::env::attached_deposit() / nicknames.len() as u128;
        if attached_deposit == 0 {
            near_sdk::env::panic("Method should accept deposit.".as_bytes());
        }
        for nick in &nicknames {
            let received_tips = match self.tips.get(&nick) {
                Some(received_tips) => received_tips,
                None => 0
            };
            self.tips.insert(&nick, &(received_tips + attached_deposit));
        }
        
    }

    pub fn get_user_tips(&self, nickname: String) -> u128 {
        match self.tips.get(&nickname) {
            Some(tips) => tips,
            None => 0
        }
    }

    pub fn withdraw_tip(&mut self, nickname: String, account_id: String) {
        let tips = match self.tips.get(&nickname) {
            Some(tips) => {
                self.tips.insert(&nickname, &0);
                tips
            },
            None => 0
        };
        if tips == 0 {
            near_sdk::env::panic("No tips for withdraw.".as_bytes());
        }
        Promise::new(account_id).transfer(tips);
    }

    pub fn add_validator(&mut self, validator_pk: String) {
        self.validators.insert(&validator_pk, &true);
    }

    pub fn remove_validator(&mut self, validator_pk: String) {
        self.validators.insert(&validator_pk, &false);
    }

    pub fn commit_access_token(&mut self, commitment_hash: Vec<u8>) {
        match self.commitments.get(&commitment_hash) {
            Some(_used) => near_sdk::env::panic("This commitment already exists.".as_bytes()),
            None => {}
        }
        self.commitments.insert(&commitment_hash, &false);
    }

    pub fn withdraw_tip_validators(&mut self, nickname: String, access_token: String, account_id: String, signatures: Vec<Vec<u8>>, validator_pks: Vec<String>) {
        if signatures.len() != validator_pks.len() {near_sdk::env::panic("Wrong pks/signatures len.".as_bytes())}
        if signatures.len() == 0 {near_sdk::env::panic("No signatures provided.".as_bytes())}
        
        let mut commitment_msg = "".to_owned();
        commitment_msg.push_str(&nickname);
        commitment_msg.push_str(&access_token);
        commitment_msg.push_str(&account_id);
        let mut hasher = Sha512::new();
        hasher.update(&commitment_msg);
        let commitment_hash = hasher.finalize().to_vec();

        match self.commitments.get(&commitment_hash) {
            Some(used) => if used { near_sdk::env::panic("This commitment has been already used.".as_bytes()) },
            None => near_sdk::env::panic("This commitment doesn't exist.".as_bytes())
        }
        // Set this commitment as already used.
        self.commitments.insert(&commitment_hash, &true);

        let mut message = "".to_owned();
        message.push_str(&nickname);
        message.push_str(&access_token);

        for it in signatures.iter().zip(validator_pks.iter()) {
            let (signature, pk) = it;
            let signature = ed25519_dalek::Signature::try_from(signature.as_ref()).expect("Signature should be a valid array of 64 bytes [13, 254, 123, ...]");
            match self.validators.get(&pk) {
                Some(valid) => if !valid {near_sdk::env::panic("The validator is not valid.".as_bytes())},
                None => near_sdk::env::panic("The validator is not valid/existed.".as_bytes())
            }

            let trusted_key = ed25519_dalek::PublicKey::from_bytes(
                &bs58::decode(
                    pk,
                )
                .into_vec()
                .unwrap(),
            )
            .unwrap();

            if trusted_key.verify(message.as_bytes(), &signature).is_err() {
                near_sdk::env::panic("Wrong signature for provided content.".as_bytes());
            }

        }

        let tips = match self.tips.get(&nickname) {
            Some(tips) => {
                self.tips.insert(&nickname, &0);
                tips
            },
            None => 0
        };
        if tips == 0 {
            near_sdk::env::panic("No tips for withdraw.".as_bytes());
        }
        Promise::new(account_id).transfer(tips);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod tests {
    extern crate rand;
    use super::*;
    use near_sdk::MockedBlockchain;
    use near_sdk::{testing_env, VMContext};
    use ed25519_dalek::{Keypair, SecretKey, PublicKey};
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    fn get_context(input: Vec<u8>, is_view: bool) -> VMContext {
        VMContext {
            current_account_id: "alice_near".to_string(),
            signer_account_id: "bob_near".to_string(),
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
    fn get_default_tips_message() {
        let context = get_context(vec![], false);
        testing_env!(context);
        let contract = TipsStack::default();
        assert_eq!(
            0,
            contract.get_user_tips("alice_near".to_string())
        );
    }

    #[test]
    fn set_one_tip() {
        let mut context = get_context(vec![], false);
        let tip_amount = 3;
        context.attached_deposit = tip_amount;
        testing_env!(context);
        let mut contract = TipsStack::default();
        contract.make_tip(vec!["alice_near".to_string()]);
        assert_eq!(
            tip_amount,
            contract.get_user_tips("alice_near".to_string())
        );
    }

    #[test]
    fn set_several_tips() {
        let mut context = get_context(vec![], false);
        let tip_amount = 4;
        context.attached_deposit = tip_amount;
        testing_env!(context);
        let mut contract = TipsStack::default();
        contract.make_tip(vec!["alice_near".to_string(), "bob_near".to_string()]);
        assert_eq!(
            tip_amount / 2,
            contract.get_user_tips("alice_near".to_string())
        );
        assert_eq!(
            tip_amount / 2,
            contract.get_user_tips("bob_near".to_string())
        );
    }

    #[test]
    fn add_validator() {
        let context = get_context(vec![], false);
        testing_env!(context);

        let mut csprng = OsRng{};
        let validatork_kp = Keypair::generate(&mut csprng);
        let mut contract = TipsStack::default();
        let val_pk = bs58::encode(validatork_kp.public.as_bytes()).into_string();
        contract.add_validator(val_pk.clone());
        assert_eq!(
            contract.validators.get(&val_pk).unwrap(),
            true
        );
    }

    #[test]
    fn withdraw() {
        let mut context = get_context(vec![], false);
        let tip_amount = 4;
        context.attached_deposit = tip_amount;
        testing_env!(context);

        // add validator
        let mut csprng = OsRng{};
        let validatork_kp = Keypair::generate(&mut csprng);
        let mut contract = TipsStack::default();
        let val_pk = bs58::encode(validatork_kp.public.as_bytes()).into_string();
        contract.add_validator(val_pk.clone());

        // generate commitment hash
        let user_id = "23".to_string();
        let access_token = "some_access_token".to_string();
        let account_id = "alice_near".to_string();
        let mut commitment_msg = "".to_owned();
        commitment_msg.push_str(&user_id);
        commitment_msg.push_str(&access_token);
        commitment_msg.push_str(&account_id);
        let mut hasher = Sha512::new();
        hasher.update(&commitment_msg);
        let commitment_hash = hasher.finalize().to_vec();
        
        // Make tip
        contract.make_tip(vec![user_id.clone()]);
        assert_eq!(
            tip_amount,
            contract.get_user_tips(user_id.clone())
        );
        
        // make commitment
        contract.commit_access_token(commitment_hash);

        // Make signature
        let mut sign_message = "".to_owned();
        sign_message.push_str(&user_id);
        sign_message.push_str(&access_token);
        let signature = validatork_kp.sign(sign_message.as_bytes());

        // Withdraw
        contract.withdraw_tip_validators(user_id, access_token, account_id, vec![(&signature.to_bytes()).to_vec()], vec![val_pk]);
        assert_eq!(
            0,
            contract.get_user_tips("alice_near".to_string())
        );
    }
}

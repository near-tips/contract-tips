use crate::*;

#[near_bindgen]
impl NearTips {
    /// Sets tips for service account
    pub(crate) fn set_tips(&mut self, service_token_id: &ServiceTokenId, set_tips: u128) {
        println!("ENTER SET TIP");
        println!("ServiceTokenId: {:?}", service_token_id);
        let res = self.tips.insert(service_token_id, &set_tips);
        println!("RES: {:?}", res);
    }

    /// Decrease deposit amount for near account
    pub(crate) fn decrease_deposit(&mut self, account_token_id: &AccountTokenId, amount: u128) {
        let deposit = match self.deposits.get(account_token_id) {
            Some(deposit) => deposit,
            None => 0
        };
        println!("Dep: {}, Am: {}", &deposit, &amount);
        self.deposits.insert(account_token_id, &(deposit - amount));
    }

    /// Increase deposit amount for near account
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

    /// Accepts deposit
    pub(crate) fn deposit(&mut self) -> (AccountId, u128) {
        let account_id = env::predecessor_account_id();
        let attached_deposit = near_sdk::env::attached_deposit();
        if attached_deposit > 0 {
            self.increase_deposit(&(account_id.clone(), NEAR.to_string()), attached_deposit);
        }
        
        (account_id, attached_deposit)
    }

    /// Validates validators signature
    /// If any signature is wrong - panics
    pub(crate) fn validate_signatures(&mut self, service_id: &ServiceId, account_id: &AccountId, deadline: u64, signatures: Vec<Vec<u8>>, validators_pks: Vec<AccountId>) {
        if signatures.len() != validators_pks.len() { near_sdk::env::panic("Wrong pks/signatures len.".as_bytes()) }
        if (signatures.len() as u64) < self.validators.len() * 2 / 3 || signatures.len() == 0 { near_sdk::env::panic("Not enough validators approve.".as_bytes()) }
        if deadline < near_sdk::env::block_timestamp() { near_sdk::env::panic("Signature is not more valid because of deadline.".as_bytes()) }

        let msg = ValidatorMsg {
            service_id: service_id.clone(),
            account_id: account_id.clone(),
            deadline
        };
        let msg = msg.try_to_vec().unwrap();
        let mut used_validators = Vec::new();
        for it in signatures.iter().zip(validators_pks.iter()) {
            let (signature, pk) = it;
            let signature = ed25519_dalek::Signature::try_from(signature.as_ref()).expect("Signature should be a valid array of 64 bytes [13, 254, 123, ...]");
            let trusted_key = ed25519_dalek::PublicKey::from_bytes(&self.validators.get(&pk).expect("The validator is not valid/existed.")).unwrap();
            if used_validators.contains(&pk) {
                near_sdk::env::panic("The validator's signature already verified.".as_bytes())
            }
            used_validators.push(pk);

            if trusted_key.verify(&msg, &signature).is_err() {
                near_sdk::env::panic("Wrong signature for provided content.".as_bytes());
            }
        }
    }

    /// Withdraws all tips from service accounts linked to near account 
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
            self.increase_deposit(&(self.horseradish_key.clone(), NEAR.to_string()), commission_amount);
            Promise::new(account_id.to_string()).transfer(withdraw_amount);
        } else {
            near_sdk::env::panic("No linked accounts found.".as_bytes());
        }
    }

    /// Withdraws tips from service account with commission
    pub(crate) fn withdraw_tips_to_account_with_commission(&mut self, service_id: &ServiceId, account_id: &AccountId, commission: u128, is_link: bool) {
        let tip_amount = self.get_service_id_tips(service_id.clone());
        if tip_amount > 0 {
            let withdraw_amount: u128 = tip_amount * (100 - commission) / 100 - is_link as u128 * NEW_LINK_PRICE;
            let commission_amount: u128 = tip_amount * (commission) / 100;
            self.set_tips(&(service_id.clone(), NEAR.to_string()), 0);
            self.increase_deposit(&(self.horseradish_key.clone(), NEAR.to_string()), commission_amount);
            Promise::new(account_id.to_string()).transfer(withdraw_amount);
        }
    }

}
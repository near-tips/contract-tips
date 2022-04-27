use crate::*;

#[near_bindgen]
impl NearTips {

    pub(crate) fn only_horseradish(&self) {
        assert_eq!(env::predecessor_account_id(), self.horseradish_key, "You are not a horseradish to call this method.")
    }

    pub fn change_horseradish(&mut self, new_horseradish: AccountId) {
        self.only_horseradish();
        self.horseradish_key = new_horseradish;
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

    // Migration function.
    // For next version upgrades, change this function.
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let contract: NearTips = env::state_read().expect("ERR_NOT_INITIALIZED");
        contract
    }
}


#[cfg(target_arch = "wasm32")]
mod upgrade {
    use near_sdk::env::BLOCKCHAIN_INTERFACE;
    use near_sdk::Gas;

    use super::*;

    const BLOCKCHAIN_INTERFACE_NOT_SET_ERR: &str = "Blockchain interface not set.";

    /// Gas for calling migration call.
    pub const GAS_FOR_MIGRATE_CALL: Gas = 5_000_000_000_000;

    /// Self upgrade and call migrate, optimizes gas by not loading into memory the code.
    /// Takes as input non serialized set of bytes of the code.
    #[no_mangle]
    pub extern "C" fn upgrade() {
        env::setup_panic_hook();
        env::set_blockchain_interface(Box::new(near_blockchain::NearBlockchain {}));
        let contract: NearTips = env::state_read().expect("ERR_CONTRACT_IS_NOT_INITIALIZED");
        contract.assert_owner();
        let current_id = env::current_account_id().into_bytes();
        let method_name = "migrate".as_bytes().to_vec();
        unsafe {
            BLOCKCHAIN_INTERFACE.with(|b| {
                // Load input into register 0.
                b.borrow()
                    .as_ref()
                    .expect(BLOCKCHAIN_INTERFACE_NOT_SET_ERR)
                    .input(0);
                let promise_id = b
                    .borrow()
                    .as_ref()
                    .expect(BLOCKCHAIN_INTERFACE_NOT_SET_ERR)
                    .promise_batch_create(current_id.len() as _, current_id.as_ptr() as _);
                b.borrow()
                    .as_ref()
                    .expect(BLOCKCHAIN_INTERFACE_NOT_SET_ERR)
                    .promise_batch_action_deploy_contract(promise_id, u64::MAX as _, 0);
                let attached_gas = env::prepaid_gas() - env::used_gas() - GAS_FOR_MIGRATE_CALL;
                b.borrow()
                    .as_ref()
                    .expect(BLOCKCHAIN_INTERFACE_NOT_SET_ERR)
                    .promise_batch_action_function_call(
                        promise_id,
                        method_name.len() as _,
                        method_name.as_ptr() as _,
                        0 as _,
                        0 as _,
                        0 as _,
                        attached_gas,
                    );
            });
        }
    }

}
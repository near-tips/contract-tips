use crate::*;

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

        let access_key = "4U9BG7i8*dhMsKThlPn7MA))";
        let account_id = "carol_near";
        let service_id = ServiceId{ service: Service::Stackoverflow, id: '1'.to_string() };
        let deadline: u64 = 1644359955;//{
        //     let start = SystemTime::now();
        //     start
        //     .duration_since(UNIX_EPOCH)
        //     .expect("Time went backwards").as_secs() + 10000
        // };
        let msg = ValidatorMsg {
            service_id: service_id.clone(),
            account_id: account_id.to_string(),
            deadline
        };
        hasher.update(&msg.try_to_vec().unwrap());

        println!("msg: {:?}", hex::encode(msg.try_to_vec().unwrap()));
        println!("service_id: {:?}", hex::encode(&service_id.try_to_vec().unwrap()));
        println!("account_id: {:?}", &account_id.as_bytes());
        println!("deadline: {}", &deadline);
        let ch = hasher.clone();
        let msg_hash = ch.finalize();
        println!("hash: {}", hex::encode(&msg_hash));
        println!("hash bytes: {:?}", &msg_hash);

        println!("{} - {:?}",deadline.clone(), deadline.to_be_bytes());
        let signature = validatork_kp.sign(&msg.try_to_vec().unwrap());
        // let signature = validatork_kp.sign_prehashed(hasher, None).unwrap();

        contract.link_account(service_id.clone(), account_id.to_string(), U64(deadline), vec![signature.to_bytes().to_vec()], vec![val_pk]);
        let accs = contract.get_linked_accounts(account_id.to_string());
        assert_eq!(
            accs.len(),
            1
        );

        // Send tips
        
        contract.send_tips(vec![service_id], U128(tip_amount as u128));
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
        let account_id = "receiver_near";
        let service_id = ServiceId{ service: Service::Stackoverflow, id: '1'.to_string() };
        let deadline = 1644359955;
        let msg = ValidatorMsg {
            service_id: service_id.clone(),
            account_id: account_id.to_string(),
            deadline
        };

        hasher.update(&msg.try_to_vec().unwrap());

        println!("service_id: {:?}", &service_id.try_to_vec().unwrap());
        println!("account_id: {}", &account_id);
        println!("deadline: {}", &deadline);
        let ch = hasher.clone();
        println!("hash: {:?}", &ch.finalize());

        println!("{} - {:?}",deadline.clone(), deadline.to_be_bytes());
        let signature = validatork_kp.sign(&msg.try_to_vec().unwrap());
        // let signature = validatork_kp.sign_prehashed(hasher, None).unwrap();

        // Send tips
        contract.send_tips(vec![service_id.clone()], U128(tip_amount as u128));
        contract.withdraw_tips_to(service_id.clone(), account_id.to_string(), U64(deadline), vec![signature.to_bytes().to_vec()], vec![val_pk]);

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
        let deadline: u64 = 1651531536353000000;
        let account_id = "verkhohliad.testnet";
        let service_id = ServiceId{
            service: Service::Stackoverflow,
            id: "17694405".to_string()
        };
        let msg = ValidatorMsg {
            service_id: service_id.clone(),
            account_id: account_id.to_string(),
            deadline
        };
        let msg = msg.try_to_vec().unwrap();
        println!("MSG: {:?}", &msg);

        let signature = hex::decode("83838d99b383098354ac52c4360f04f378001344ae686d1ca04a785e38306fb8b92f8375ce071b4737322a56a221d0c633e0d7ff52b899079ab1909868d3800a").unwrap();
        let key_as_bytes = &bs58::decode("Ah51gcfsTnrnvfhj6AERkEWz3E8U1yiRqhPRGza1Nu6p").into_vec().unwrap();
        let trusted_key = ed25519_dalek::PublicKey::from_bytes(key_as_bytes).unwrap();
        let signature = ed25519_dalek::Signature::try_from(signature.as_ref()).unwrap();
        println!("Sig validation: {}", trusted_key.verify(&msg, &signature).is_ok());


        let rec = vec![
            0,   8,   0,   0,   0,  49,  55,  54,  57,  52,
           52,  48,  53,  16,   0,   0,   0, 118, 101, 114,
          107, 104, 111, 104, 108, 105,  97, 100,  46, 110,
          101,  97, 114,  64, 250, 172, 159,  46, 107, 235,
           22
        ];
        let rec_msg = ValidatorMsg::try_from_slice(&rec).unwrap();
        println!("ValidatorMsg: {:?}", rec_msg);

    }
}

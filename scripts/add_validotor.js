import * as nearAPI from "near-api-js";
import * as path from 'path';
import { homedir } from "os";

const { connect, keyStores } = nearAPI;

const CREDENTIALS_DIR = ".near-credentials";
const credentialsPath = path.join(homedir(), CREDENTIALS_DIR);
const keyStore = new keyStores.UnencryptedFileSystemKeyStore(credentialsPath);

const config = {
  networkId: "testnet",
  keyStore: keyStore,
  nodeUrl: "https://rpc.testnet.near.org",
  walletUrl: "https://wallet.testnet.near.org",
  helperUrl: "https://helper.testnet.near.org",
  explorerUrl: "https://explorer.testnet.near.org",
};

(async () => {
    try {
       // connect to NEAR
        const near = await connect(config);
        const account = await near.account("norfolks.testnet");

        const contract = new nearAPI.Contract(
            account, // the account object that is connecting
            "norfolks.testnet",
            {
                // name of contract you're connecting to
                viewMethods: ["get_user_tips"], // view methods do not change state but usually return a value
                changeMethods: ["add_validator"], // change methods modify state
                sender: account, // account object to initialize and sign transactions.
            }
        );
        
        console.log(await contract.add_validator(
            {
                validator_pk: "AejpTNQSuSN1vCZaeYRgoUeJa6dZL4orSVFmPidbRofa" // argument name and value - pass empty object if no args required
            }
        ))
    } catch (e) {
        console.log(e)
    }
})();


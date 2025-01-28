use crate::contract::{RegistrationRequest, VerificationRequest, WebAuthnAction};
use hyle_sdk::{Blob, ContractInput, StateDigest};
use std::fs::File;
use std::io::BufReader;

pub fn get_claim_tweet_input() -> WebAuthnAction {
    let file = File::open("./proof-examples/login.json").unwrap();
    let reader = BufReader::new(file);

    let config_contract: VerificationRequest =
        serde_json::from_reader(reader).expect("cannot read");

    // reclaim ZKVM contract blob format is in JSON

    let blobs = vec![Blob {
        contract_name: hyle_sdk::ContractName("buy-my-tweet-webauthn".into()),
        data: hyle_sdk::BlobData(
            serde_json::to_string(&config_contract)
                .expect("cannot convert")
                .as_bytes()
                .to_vec(),
        ),
    }];

    WebAuthnAction::Verify {
        input: ContractInput {
            initial_state: StateDigest(vec![]),
            blobs,
            identity: hyle_sdk::Identity("buy-my-tweet-webauthn".into()),
            index: hyle_sdk::BlobIndex(0),
            private_blob: hyle_sdk::BlobData(vec![]),
            tx_hash: hyle_sdk::TxHash("".into()),
        },
    }
}

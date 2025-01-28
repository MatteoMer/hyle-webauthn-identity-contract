use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hyle_sdk::{
    flatten_blobs, identity_provider::IdentityVerification, Blob, ContractInput, Digestable,
    HyleOutput, StateDigest,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256}; // Using RustCrypto's SHA-256 implementation
use std::collections::BTreeMap;

use crate::ZkvmProcessError;

#[derive(Serialize, Deserialize)]
pub enum WebAuthnAction {
    Register { input: ContractInput },
    Verify { input: ContractInput },
}

#[derive(Debug)]
pub enum WebAuthnError {
    InvalidRpIdHash,
    InvalidSignature,
    InvalidChallenge,
    InvalidAuthData,
    UserAlreadyExists,
    UserNotFound,
    InvalidInput,
    InvalidAttestation,
}

impl From<WebAuthnError> for &'static str {
    fn from(error: WebAuthnError) -> Self {
        match error {
            WebAuthnError::InvalidSignature => "Invalid signature",
            WebAuthnError::InvalidChallenge => "Invalid challenge",
            WebAuthnError::UserAlreadyExists => "User already exists",
            WebAuthnError::UserNotFound => "User not found",
            WebAuthnError::InvalidInput => "Invalid input",
            WebAuthnError::InvalidAuthData => "Invalid authenticator data",
            WebAuthnError::InvalidRpIdHash => "Invalid RP ID hash",
            WebAuthnError::InvalidAttestation => "Invalid attestation",
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientData {
    r#type: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthenticatorResponse {
    #[serde(rename = "attestationObject")]
    attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    transports: Option<Vec<String>>,
    #[serde(rename = "publicKeyAlgorithm")]
    public_key_algorithm: i32,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct WebAuthnAttestation {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: String,
    response: AuthenticatorResponse,
    r#type: String,
    #[serde(rename = "clientExtensionResults")]
    client_extension_results: serde_json::Value,
    #[serde(rename = "authenticatorAttachment")]
    authenticator_attachment: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegistrationRequest {
    pub username: String,
    pub attestation: WebAuthnAttestation,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct WebAuthnAssertion {
    id: String,
    #[serde(rename = "rawId")]
    raw_id: String,
    response: AuthenticatorAssertionResponse,
    r#type: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct VerificationData {
    assertion: WebAuthnAssertion,
    expected_challenge: String, // base64url-encoded tx_hash
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationRequest {
    pub username: String,
    pub verification_data: String, // Serialized VerificationData
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebAuthnAccountInfo {
    public_key: Vec<u8>,
    credential_id: Vec<u8>,
    sign_count: u64,
    nonce: u32,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebAuthnContractState {
    rp_id: String,
    identities: BTreeMap<String, WebAuthnAccountInfo>,
}

// COSE key constants
const COSE_KTY_EC2: i128 = 2;
const COSE_ALG_ES256: i128 = -7;
const COSE_CRV_P256: i128 = 1;
const COSE_KEY_TYPE: i128 = 1;
const COSE_KEY_ALG: i128 = 3;
const COSE_KEY_CRV: i128 = -1;
const COSE_KEY_X: i128 = -2;
const COSE_KEY_Y: i128 = -3;

impl WebAuthnContractState {
    pub fn new() -> Self {
        Self {
            // TODO CHANGE
            rp_id: "localhost".to_string(),
            identities: BTreeMap::new(),
        }
    }

    pub fn get_nonce(&self, username: &str) -> Result<u32, WebAuthnError> {
        let info = self
            .identities
            .get(username)
            .ok_or(WebAuthnError::UserNotFound)?;
        Ok(info.nonce)
    }

    fn decode_base64_url(input: &str) -> Result<Vec<u8>, &'static str> {
        URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| "Failed to decode base64url")
    }

    fn parse_cose_key(&self, cose_key: &[u8]) -> Result<Vec<u8>, &'static str> {
        let value: serde_cbor::Value =
            serde_cbor::from_slice(cose_key).map_err(|_| "Invalid COSE key format")?;

        let key_map = match value {
            serde_cbor::Value::Map(map) => map,
            _ => return Err("COSE key must be a map"),
        };

        // Verify key type is EC2
        let kty = match key_map
            .get(&serde_cbor::Value::Integer(COSE_KEY_TYPE))
            .ok_or("Missing kty")?
        {
            serde_cbor::Value::Integer(n) => *n,
            _ => return Err("Invalid kty type"),
        };
        if kty != COSE_KTY_EC2 {
            return Err("Unsupported key type, expected EC2");
        }

        // Verify algorithm is ES256
        let alg = match key_map
            .get(&serde_cbor::Value::Integer(COSE_KEY_ALG))
            .ok_or("Missing alg")?
        {
            serde_cbor::Value::Integer(n) => *n,
            _ => return Err("Invalid alg type"),
        };
        if alg != COSE_ALG_ES256 {
            return Err("Unsupported algorithm, expected ES256");
        }

        // Verify curve is P-256
        let crv = match key_map
            .get(&serde_cbor::Value::Integer(COSE_KEY_CRV))
            .ok_or("Missing crv")?
        {
            serde_cbor::Value::Integer(n) => *n,
            _ => return Err("Invalid crv type"),
        };
        if crv != COSE_CRV_P256 {
            return Err("Unsupported curve, expected P-256");
        }

        // Get x coordinate
        let x = match key_map
            .get(&serde_cbor::Value::Integer(COSE_KEY_X))
            .ok_or("Missing x coordinate")?
        {
            serde_cbor::Value::Bytes(bytes) => bytes,
            _ => return Err("Invalid x coordinate type"),
        };

        // Get y coordinate
        let y = match key_map
            .get(&serde_cbor::Value::Integer(COSE_KEY_Y))
            .ok_or("Missing y coordinate")?
        {
            serde_cbor::Value::Bytes(bytes) => bytes,
            _ => return Err("Invalid y coordinate type"),
        };

        if x.len() != 32 || y.len() != 32 {
            return Err("Invalid coordinate length, expected 32 bytes");
        }

        // Construct uncompressed EC public key (0x04 || x || y)
        let mut public_key = Vec::with_capacity(65);
        public_key.push(0x04); // Uncompressed point format
        public_key.extend_from_slice(x);
        public_key.extend_from_slice(y);
        Ok(public_key)
    }

    fn verify_attestation(
        &self,
        client_data_json: &str,
        auth_data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<(), WebAuthnError> {
        let client_data: ClientData =
            serde_json::from_str(client_data_json).map_err(|_| WebAuthnError::InvalidInput)?;

        // Verify origin
        if !client_data.origin.starts_with("http://localhost") {
            return Err(WebAuthnError::InvalidInput);
        }

        // Verify type
        if client_data.r#type != "webauthn.create" {
            return Err(WebAuthnError::InvalidInput);
        }

        // Hash the client data
        let mut hasher = Sha256::new();
        hasher.update(client_data_json.as_bytes());
        let client_data_hash = hasher.finalize();

        // Construct the signed data
        let mut signed_data = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed_data.extend_from_slice(auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        // Verify signature
        let verifying_key =
            VerifyingKey::from_sec1_bytes(public_key).map_err(|_| WebAuthnError::InvalidInput)?;

        let signature =
            Signature::from_der(signature).map_err(|_| WebAuthnError::InvalidSignature)?;

        verifying_key
            .verify(&signed_data, &signature)
            .map_err(|_| WebAuthnError::InvalidSignature)
    }

    fn validate_rpid_hash(&self, auth_data: &[u8]) -> Result<(), WebAuthnError> {
        if auth_data.len() < 32 {
            return Err(WebAuthnError::InvalidAuthData);
        }

        let received_rp_id_hash = &auth_data[..32];
        let mut hasher = Sha256::new();
        hasher.update(self.rp_id.as_bytes());
        let expected_rp_id_hash = hasher.finalize();

        if received_rp_id_hash != expected_rp_id_hash.as_slice() {
            return Err(WebAuthnError::InvalidRpIdHash);
        }

        Ok(())
    }

    fn parse_auth_data(&self, auth_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u64), WebAuthnError> {
        // Validate minimum length for header
        if auth_data.len() < 37 {
            return Err(WebAuthnError::InvalidAuthData);
        }

        // Validate RP ID hash
        self.validate_rpid_hash(auth_data)?;

        // Check attestation data flag
        let flags = auth_data[32];
        if flags & 0x40 == 0 {
            return Err(WebAuthnError::InvalidAuthData);
        }

        // Extract sign count (4 bytes starting at index 33)
        let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap()) as u64;

        // Skip to credential data
        let mut pos = 37;
        pos += 16; // Skip AAGUID

        // Read credential ID length
        if auth_data.len() < pos + 2 {
            return Err(WebAuthnError::InvalidAuthData);
        }
        let cred_id_len = u16::from_be_bytes([auth_data[pos], auth_data[pos + 1]]) as usize;
        pos += 2;

        // Extract credential ID
        if auth_data.len() < pos + cred_id_len {
            return Err(WebAuthnError::InvalidAuthData);
        }
        let credential_id = auth_data[pos..pos + cred_id_len].to_vec();
        pos += cred_id_len;

        // Parse public key
        let public_key = self
            .parse_cose_key(&auth_data[pos..])
            .map_err(|_| WebAuthnError::InvalidInput)?;

        Ok((credential_id, public_key, sign_count))
    }
}

impl IdentityVerification for WebAuthnContractState {
    fn register_identity(
        &mut self,
        username: &str,
        attestation_str: &str,
    ) -> Result<(), &'static str> {
        // Check if user already exists
        if self.identities.contains_key(username) {
            return Err(WebAuthnError::UserAlreadyExists.into());
        }

        // Parse attestation object
        let attestation: WebAuthnAttestation =
            serde_json::from_str(attestation_str).map_err(|_| WebAuthnError::InvalidInput)?;

        // Parse and verify client data
        let client_data_bytes = URL_SAFE_NO_PAD
            .decode(&attestation.response.client_data_json)
            .map_err(|_| WebAuthnError::InvalidInput)?;

        let client_data: ClientData =
            serde_json::from_slice(&client_data_bytes).map_err(|_| WebAuthnError::InvalidInput)?;

        // Verify type is webauthn.create
        if client_data.r#type != "webauthn.create" {
            return Err(WebAuthnError::InvalidInput.into());
        }

        // Parse attestation object
        let attestation_bytes = URL_SAFE_NO_PAD
            .decode(&attestation.response.attestation_object)
            .map_err(|_| WebAuthnError::InvalidInput)?;

        let attestation_obj = serde_cbor::from_slice::<serde_cbor::Value>(&attestation_bytes)
            .map_err(|_| WebAuthnError::InvalidAttestation)?;

        // Extract auth_data and verify fmt is "none"
        let auth_data = match attestation_obj {
            serde_cbor::Value::Map(map) => {
                // Verify fmt is "none"
                let fmt = map
                    .get(&serde_cbor::Value::Text("fmt".to_string()))
                    .and_then(|v| match v {
                        serde_cbor::Value::Text(t) => Some(t.as_str()),
                        _ => None,
                    })
                    .ok_or(WebAuthnError::InvalidAttestation)?;

                if fmt != "none" {
                    return Err(WebAuthnError::InvalidAttestation.into());
                }

                // Get authData
                map.get(&serde_cbor::Value::Text("authData".to_string()))
                    .and_then(|v| match v {
                        serde_cbor::Value::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .ok_or(WebAuthnError::InvalidAttestation)?
            }
            _ => return Err(WebAuthnError::InvalidAttestation.into()),
        };

        // Parse auth data to get credential ID, public key, and sign count
        let (credential_id, public_key, sign_count) = self.parse_auth_data(&auth_data)?;

        // Store the new identity
        let account_info = WebAuthnAccountInfo {
            public_key,
            credential_id,
            sign_count,
            nonce: 0,
        };

        self.identities.insert(username.to_string(), account_info);
        Ok(())
    }

    fn verify_identity(
        &mut self,
        username: &str,
        nonce: u32,
        verification_data_str: &str, // Now contains both assertion and challenge
    ) -> Result<bool, &'static str> {
        // Deserialize the combined data
        let verification_data: VerificationData =
            serde_json::from_str(verification_data_str).map_err(|_| "Invalid verification data")?;

        let assertion = verification_data.assertion;
        let expected_challenge = verification_data.expected_challenge;

        let account_info = self
            .identities
            .get_mut(username)
            .ok_or("Identity not found")?;

        if nonce != account_info.nonce {
            return Err("Invalid nonce");
        }

        // Decode client data
        let client_data_bytes = Self::decode_base64_url(&assertion.response.client_data_json)?;
        let client_data_str = String::from_utf8(client_data_bytes.clone())
            .map_err(|_| "Invalid client data encoding")?;
        let client_data: ClientData =
            serde_json::from_str(&client_data_str).map_err(|_| "Invalid client data format")?;

        // Validate challenge matches tx_hash
        if client_data.challenge != expected_challenge {
            return Err("Invalid challenge");
        }

        // Validate type and origin
        if client_data.r#type != "webauthn.get" {
            return Err("Invalid assertion type");
        }
        if !client_data.origin.starts_with("http://localhost") {
            return Err("Invalid origin");
        }

        // Decode auth data and signature
        let auth_data = Self::decode_base64_url(&assertion.response.authenticator_data)?;
        let signature = Self::decode_base64_url(&assertion.response.signature)?;

        // Hash CLIENT DATA BYTES (decoded from base64url)
        let mut hasher = Sha256::new();
        hasher.update(&client_data_str);
        let client_data_hash = hasher.finalize();

        // Construct signed data
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_data_hash);

        // Verify signature
        let verifying_key = VerifyingKey::from_sec1_bytes(&account_info.public_key)
            .map_err(|_| "Invalid public key")?;

        let signature = Signature::from_der(&signature).map_err(|_| "Invalid signature format")?;

        match verifying_key.verify(&signed_data, &signature) {
            Ok(_) => {
                account_info.nonce += 1;
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn get_identity_info(&self, username: &str) -> Result<String, &'static str> {
        match self.identities.get(username) {
            Some(info) => Ok(serde_json::to_string(&info).map_err(|_| "Failed to serialize")?),
            None => Err("Identity not found"),
        }
    }
}

impl Default for WebAuthnContractState {
    fn default() -> Self {
        Self::new()
    }
}

impl Digestable for WebAuthnContractState {
    fn as_digest(&self) -> hyle_sdk::StateDigest {
        hyle_sdk::StateDigest(serde_json::to_vec(self).expect("Failed to encode WebAuthn state"))
    }
}

impl From<hyle_sdk::StateDigest> for WebAuthnContractState {
    fn from(state: hyle_sdk::StateDigest) -> Self {
        if state.0 == Vec::<u8>::new() {
            WebAuthnContractState::new()
        } else {
            serde_json::from_slice(&state.0)
                .map_err(|_| "Could not decode WebAuthn state".to_string())
                .unwrap()
        }
    }
}

impl From<WebAuthnContractState> for hyle_sdk::StateDigest {
    fn from(state: WebAuthnContractState) -> Self {
        hyle_sdk::StateDigest(serde_json::to_vec(&state).expect("Failed to encode WebAuthn state"))
    }
}

fn register_action(input: ContractInput) -> Result<HyleOutput, ContractError> {
    let mut state: WebAuthnContractState = input.initial_state.clone().into();

    let contract_blob: &Blob = input
        .blobs
        .get(input.index.0)
        .ok_or(ContractError::InvalidInput("Could not get blob"))?;

    // Extract registration data from the blob
    let request: RegistrationRequest = serde_json::from_slice(&contract_blob.data.0)
        .map_err(|_| ContractError::InvalidInput("Could not parse registration request"))?;
    let username = request.username;
    let attestation = request.attestation;

    // Perform registration
    let attestation_str =
        serde_json::to_string(&attestation).map_err(|_| ContractError::SerializationError)?;

    state
        .register_identity(&username, &attestation_str)
        .map_err(|e| ContractError::WebAuthnError(e))?;

    Ok(HyleOutput {
        version: 1,
        initial_state: input.initial_state.clone(),
        next_state: state.clone().into(),
        identity: input.identity.clone(),
        index: input.index.clone(),
        blobs: flatten_blobs(&input.blobs),
        success: true,
        program_outputs: vec![],
        tx_hash: input.tx_hash.clone(),
    })
}

fn verify_action(input: ContractInput) -> Result<HyleOutput, ContractError> {
    let mut state: WebAuthnContractState = input.initial_state.clone().into();
    let contract_blob: &Blob = input
        .blobs
        .get(input.index.0)
        .ok_or(ContractError::InvalidInput("Could not get blob"))?;

    let request: VerificationRequest = serde_json::from_slice(&contract_blob.data.0)
        .map_err(|_| ContractError::InvalidInput("Invalid verification request"))?;
    let username = request.username;
    let assertion = request.assertion;

    let nonce = state
        .get_nonce(&username)
        .map_err(|e| ContractError::WebAuthnError(e.into()))?;

    // Convert tx_hash to base64url string
    let expected_challenge = URL_SAFE_NO_PAD.encode(&input.tx_hash.0);

    let assertion_str =
        serde_json::to_string(&assertion).map_err(|_| ContractError::SerializationError)?;

    let success = state
        .verify_identity(&username, nonce, &assertion_str, &expected_challenge)
        .map_err(|e| ContractError::WebAuthnError(e))?;

    Ok(HyleOutput {
        version: 1,
        initial_state: input.initial_state.clone(),
        next_state: state.into(),
        identity: input.identity.clone(),
        index: input.index.clone(),
        blobs: flatten_blobs(&input.blobs),
        success,
        program_outputs: vec![],
        tx_hash: input.tx_hash.clone(),
    })
}
pub fn execute_action(action: WebAuthnAction) -> Result<HyleOutput, ContractError> {
    match action {
        WebAuthnAction::Register { input } => register_action(input),
        WebAuthnAction::Verify { input } => verify_action(input),
    }
}

#[derive(Debug)]
pub enum ContractError {
    InvalidInput(&'static str),
    SerializationError,
    WebAuthnError(&'static str),
}

impl From<ContractError> for ZkvmProcessError {
    fn from(error: ContractError) -> Self {
        match error {
            _ => ZkvmProcessError::ContractError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyle_sdk::{Blob, BlobIndex, ContractInput, Identity, StateDigest, TxHash};
    use std::fs::File;
    use std::io::BufReader;

    fn load_registration_request() -> RegistrationRequest {
        let file =
            File::open("../proof-examples/register.json").expect("Failed to open register.json");
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).expect("Failed to parse registration request")
    }

    fn load_verification_request() -> VerificationRequest {
        let file = File::open("../proof-examples/login.json").expect("Failed to open login.json");
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).expect("Failed to parse verification request")
    }

    fn create_blob<T: Serialize>(data: &T) -> Blob {
        Blob {
            contract_name: hyle_sdk::ContractName("buy-my-tweet-webauthn".into()),
            data: hyle_sdk::BlobData(
                serde_json::to_string(data)
                    .expect("Serialization failed")
                    .into_bytes(),
            ),
        }
    }

    #[test]
    fn test_full_flow() {
        // ==== Registration Phase ====
        let registration_data = load_registration_request();
        let register_blob = create_blob(&registration_data);

        let register_action = WebAuthnAction::Register {
            input: ContractInput {
                initial_state: StateDigest(vec![]), // Initial empty state
                blobs: vec![register_blob],
                identity: Identity("buy-my-tweet-webauthn".into()),
                index: BlobIndex(0),
                private_blob: hyle_sdk::BlobData(vec![]),
                tx_hash: TxHash("".into()),
            },
        };

        // Execute registration
        let register_result = execute_action(register_action).expect("Registration failed");

        // Verify registration succeeded
        assert!(register_result.success, "Registration should succeed");
        let new_state: WebAuthnContractState = register_result.next_state.clone().into();
        assert!(
            new_state
                .identities
                .contains_key(&registration_data.username),
            "User should be registered"
        );

        // ==== Login Phase ====
        let verification_data = load_verification_request();
        let verify_blob = create_blob(&verification_data);

        // Use the state from registration as initial state for verification
        let verify_action = WebAuthnAction::Verify {
            input: ContractInput {
                initial_state: register_result.next_state,
                blobs: vec![verify_blob],
                identity: Identity("buy-my-tweet-webauthn".into()),
                index: BlobIndex(0),
                private_blob: hyle_sdk::BlobData(vec![]),
                tx_hash: TxHash("".into()),
            },
        };

        // Execute verification
        let verify_result = execute_action(verify_action).expect("Verification failed");

        // Verify login succeeded
        assert!(verify_result.success, "Login should succeed");

        // Verify nonce incremented
        let post_login_state: WebAuthnContractState = verify_result.next_state.into();
        let user_info = post_login_state
            .identities
            .get(&verification_data.username)
            .expect("User should exist after login");
        assert_eq!(
            user_info.nonce, 1,
            "Nonce should increment after successful login"
        );
    }
}

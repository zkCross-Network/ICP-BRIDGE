use crate::helper::get_network_config;
use candid::CandidType;
use candid::Principal;
use ethers_core::types::Address;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
};
use ic_cdk::id;
use k256::PublicKey;
use serde::Serialize;

use lazy_static::lazy_static;
use sha3::{Digest, Keccak256};
use std::sync::Mutex;

pub struct PublicKeyStore {
    pub public_key_hex: String,
}
// Create a static instance of PublicKeyStore using lazy_static
lazy_static! {
    static ref PUBLIC_KEY_STORE: Mutex<Option<PublicKeyStore>> = Mutex::new(None);
}

impl PublicKeyStore {
    // Function to store the public key
    pub fn store(public_key_hex: String) {
        let mut store = PUBLIC_KEY_STORE.lock().unwrap();
        *store = Some(PublicKeyStore { public_key_hex });
    }

    // Function to retrieve the stored public key (returns an Option)
    pub fn get() -> Option<String> {
        let store = PUBLIC_KEY_STORE.lock().unwrap();
        store.as_ref().map(|s| s.public_key_hex.clone())
    }
}

#[ic_cdk::update]
pub async fn generate_key_pair() -> Result<String, String> {
    let (_, ecdsa_key) = get_network_config(); // Destructure the tuple to get only the address

    // Request the public key from the management canister

    let canister_principal = id();
    let canister_id_blob = ic_cdk::id().as_slice().to_vec();

    // let derivation_path: Vec<Vec<u8>> = vec![vec![132, 121, 211], vec![102, 112, 213],vec![121, 234, 211]]; // Example derivation path
    //  let derivation_path=[];
    let request = EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![canister_id_blob],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: ecdsa_key.to_string(),
        },
    };

    let (response,) = ecdsa_public_key(request)
        .await
        .map_err(|e| format!("ecdsa_public_key failed {:?}", e))?;

    ic_cdk::println!("response , {:?}", response);

    // Convert the public key bytes to an Ethereum address
    let public_key_hex = hex::encode(&response.public_key);
    ic_cdk::println!("stored public_key_hex: {:?}", public_key_hex);

    PublicKeyStore::store(public_key_hex.clone()); // Store the public key

    let ethereum_address = pubkey_bytes_to_address(&response.public_key);
    ic_cdk::println!("Public key: {}", public_key_hex);
    ic_cdk::println!(
        "Ethereum address: {} ,canister_principal {}",
        ethereum_address,
        canister_principal
    );

    // Return the Ethereum address
    Ok(ethereum_address)
}

fn pubkey_bytes_to_address(pubkey_bytes: &[u8]) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let key =
        PublicKey::from_sec1_bytes(pubkey_bytes).expect("failed to parse the public key as SEC1");
    let point = key.to_encoded_point(false);
    let point_bytes = point.as_bytes();
    assert_eq!(point_bytes[0], 0x04);

    let hash = Keccak256::digest(&point_bytes[1..]);

    let address = Address::from_slice(&hash[12..32]);
    ethers_core::utils::to_checksum(&address.into(), None)
}

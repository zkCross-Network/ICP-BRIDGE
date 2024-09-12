use ethers_core::types::Address;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
};
use ic_cdk::id;
use k256::PublicKey;
use sha3::{Digest, Keccak256};

#[ic_cdk::update]
pub async fn generate_key_pair() -> Result<String, String> {
    // Request the public key from the management canister

    let canister_principal = id();

    let request = EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![],
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "dfx_test_key".to_string(),
        },
    };

    let (response,) = ecdsa_public_key(request)
        .await
        .map_err(|e| format!("ecdsa_public_key failed {:?}", e))?;

    // Convert the public key bytes to an Ethereum address
    let public_key_hex = hex::encode(&response.public_key);

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

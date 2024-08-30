use candid::CandidType;
use ic_cdk::api::management_canister::ecdsa::{
    ecdsa_public_key, sign_with_ecdsa, EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgument,
    SignWithEcdsaArgument,
};

use serde::{Serialize,Deserialize};
use std::convert::TryFrom;
use sha2::Digest;
use hex;
use rlp::{RlpStream, Encodable, Decodable};
use rlp_derive::{RlpEncodable, RlpDecodable};

#[derive(CandidType, Serialize, Debug, RlpEncodable, RlpDecodable,Deserialize)]
struct EthereumTransaction {
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: String,
    value: u64,
    data: Vec<u8>,
    chain_id: u64,
}

#[derive(CandidType, Serialize, Debug)]
struct SignedTransaction {
    raw_transaction: String,
    transaction_hash: String,
}

#[ic_cdk::update]
async fn sign_transaction(tx: EthereumTransaction) -> Result<SignedTransaction, String> {
    // Step 1: Serialize the transaction data
    let rlp_encoded_tx = rlp::encode(&tx);

    ic_cdk::println!("rlp_encoded_tx   :{:?} ",rlp_encoded_tx);

    // Step 2: Hash the RLP-encoded transaction
    let tx_hash = sha256(&rlp_encoded_tx);

    ic_cdk::println!("tx_hash   :{:?} ",tx_hash);

    // Step 3: Sign the transaction hash using ECDSA
    let request = SignWithEcdsaArgument {
        message_hash: tx_hash.to_vec(),
        derivation_path: vec![], // Update this if needed
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };


    ic_cdk::println!("request   :{:?} ",request);

    let (response,) = sign_with_ecdsa(request)
        .await
        .map_err(|e| format!("sign_with_ecdsa failed: {}", e.1))?;

        ic_cdk::println!("response   :{:?} ",response);

    // Step 4: Deserialize and format the signature (r, s, v) correctly
    let signature = response.signature;
    ic_cdk::println!("Signature one  :{:?} ",signature);
    let (r, s, v) = parse_signature(&signature, tx.chain_id)?;

    // Create the raw transaction with the signature
    let raw_transaction = create_raw_transaction(&rlp_encoded_tx, r, s, v);

    // Calculate the transaction hash for broadcasting
    let transaction_hash = sha256(&raw_transaction);

    

    Ok(SignedTransaction {
        raw_transaction: hex::encode(raw_transaction),
        transaction_hash: hex::encode(transaction_hash),
    })
}

fn create_raw_transaction(rlp_encoded_tx: &[u8], r: Vec<u8>, s: Vec<u8>, v: u64) -> Vec<u8> {
    let mut raw_tx = rlp_encoded_tx.to_vec();
    raw_tx.extend(r);
    raw_tx.extend(s);
    raw_tx.extend(v.to_le_bytes());
    raw_tx
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn parse_signature(signature: &[u8], chain_id: u64) -> Result<(Vec<u8>, Vec<u8>, u64), String> {
    ic_cdk::println!("Signature: {:?}, length: {:?}", signature, signature.len());

    let (r, s, mut v) = match signature.len() {
        65 => {
            // Handle the 65-byte signature
            let r = signature[0..32].to_vec();
            let s = signature[32..64].to_vec();
            let v = signature[64] as u64;
            (r, s, v)
        }
        64 => {
            // Handle the 64-byte signature (without v)
            let r = signature[0..32].to_vec();
            let s = signature[32..64].to_vec();
            // Default v value, or infer based on your application
            let  v = 27; // or 28, depending on your context
            (r, s, v)
        }
        _ => return Err("Invalid signature length".to_string()),
    };

    // Adjust the v value according to the chain_id if necessary
    if chain_id != 0 {
        v = v + 2 * chain_id + 35;
    }

    Ok((r, s, v))
}


#[derive(CandidType, Serialize, Debug)]
struct PublicKeyReply {
    pub public_key_hex: String,
}

#[ic_cdk::update]
async fn public_key() -> Result<PublicKeyReply, String> {
    let request = EcdsaPublicKeyArgument {
        canister_id: None,
        derivation_path: vec![],
        key_id: EcdsaKeyIds::TestKeyLocalDevelopment.to_key_id(),
    };

    let (response,) = ecdsa_public_key(request)
        .await
        .map_err(|e| format!("ecdsa_public_key failed {}", e.1))?;

    Ok(PublicKeyReply {
        public_key_hex: hex::encode(response.public_key),
    })
}

enum EcdsaKeyIds {
    #[allow(unused)]
    TestKeyLocalDevelopment,
    #[allow(unused)]
    TestKey1,
    #[allow(unused)]
    ProductionKey1,
}

impl EcdsaKeyIds {
    fn to_key_id(&self) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: match self {
                Self::TestKeyLocalDevelopment => "dfx_test_key",
                Self::TestKey1 => "test_key_1",
                Self::ProductionKey1 => "key_1",
            }
            .to_string(),
        }
    }
}

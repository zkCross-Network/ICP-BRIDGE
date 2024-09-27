use std::io::Read;
use std::str::FromStr;

use alloy_primitives::keccak256;

use candid::{Nat, Principal};


use ethers_core::types::Eip1559TransactionRequest;
use ethers_core::types::H160;
use evm_rpc_canister_types::EthSepoliaService;

use evm_rpc_canister_types::MultiSendRawTransactionResult;
use evm_rpc_canister_types::RpcServices;
use evm_rpc_canister_types::SendRawTransactionResult;
use evm_rpc_canister_types::{
    BlockTag, EvmRpcCanister, GetTransactionCountArgs, GetTransactionCountResult,
    MultiGetTransactionCountResult,
};
use ethers_core::{abi::{Contract, Token}};
use ic_cdk::api::management_canister::ecdsa::ecdsa_public_key;
use ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyArgument;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;
use ic_cdk::api::management_canister::ecdsa::SignWithEcdsaResponse;
use ic_cdk::id;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{hex, Signature, TxKind};
use ethers_core::types::Address;
use ic_cdk::api::management_canister::ecdsa::{EcdsaCurve, EcdsaKeyId, SignWithEcdsaArgument};
use ic_cdk::update;

pub const EVM_RPC_CANISTER_ID: Principal =
    Principal::from_slice(b"\x00\x00\x00\x00\x02\x30\x00\xCC\x01\x01"); // 7hfb6-caaaa-aaaar-qadga-cai
pub const EVM_RPC: EvmRpcCanister = EvmRpcCanister(EVM_RPC_CANISTER_ID);

use crate::helper::estimate_transaction_fees;
use crate::helper::get_network_config;
use crate::helper::nat_to_u256;
use crate::helper::nat_to_u64;



fn key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "dfx_test_key".to_string(), // use EcdsaKeyId::default() for mainnet use test_key_1 for testnet and dfx_test_key for local deployment
    }
}

pub async fn get_ecdsa_public_key() -> EcdsaPublicKeyResponse {
    let (pub_key,) = ecdsa_public_key(EcdsaPublicKeyArgument {
        key_id: key_id(),
        ..Default::default()
    })
    .await
    .expect("Failed to get public key");
    pub_key
}

async fn pubkey_and_signature(txhash: Vec<u8>) -> (EcdsaPublicKeyResponse, SignWithEcdsaResponse) {
    // Get the public key
    let public_key = get_ecdsa_public_key().await;
    let canister_id_blob = ic_cdk::id().as_slice().to_vec();
    // Generate the signature
    let (signature,) = sign_with_ecdsa(SignWithEcdsaArgument {
        message_hash: txhash,
        key_id: key_id(),
        ..Default::default()
    })
    .await
    .expect("Failed to generate signature");

    (public_key, signature)
}

fn y_parity(prehash: &[u8], sig: &[u8], pubkey: &[u8]) -> u64 {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let orig_key = VerifyingKey::from_sec1_bytes(pubkey).expect("failed to parse the pubkey");
    let signature = Signature::try_from(sig).unwrap();
    for parity in [0u8, 1] {
        let recid = RecoveryId::try_from(parity).unwrap();
        let recovered_key = VerifyingKey::recover_from_prehash(prehash, &signature, recid)
            .expect("failed to recover key");
        if recovered_key == orig_key {
            return parity as u64;
        }
    }

    panic!(
        "failed to recover the parity bit from a signature; sig: {}, pubkey: {}",
        hex::encode(sig),
        hex::encode(pubkey)
    )
}

#[ic_cdk::update]
pub async fn send_eth(
    to: String,
    amount: f64,
    dest_chain_id: String,
) -> Result<SendRawTransactionResult, std::string::String> {
    use ethers_core::types::U256;
    use evm_rpc_canister_types::RpcApi;
    use num_traits::ToPrimitive;
    use std::str::FromStr; // Ensure you have this import for H160

    let canister_principal = id();
    ic_cdk::println!("to: {:?}", to);

    let chain_id: u64 = dest_chain_id
        .parse::<u64>()
        .expect("Failed to parse chain ID");

    let block_tag = BlockTag::Latest;
    let (canister_address, ecdsa_key) = get_network_config();

    let get_transaction_count_args = GetTransactionCountArgs {
        address: canister_address.to_string(),
        block: block_tag,
    };
    

    let get_transaction_count_args_clone = get_transaction_count_args.clone();

    let transaction_result = EVM_RPC
        .eth_get_transaction_count(
            RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
            None,
            get_transaction_count_args_clone,
            200_000_000_000_u128,
        )
        .await
        .unwrap_or_else(|e| panic!("failed to get transaction count, error: {:?}", e));

    let transaction_count = match transaction_result.0 {
        MultiGetTransactionCountResult::Consistent(consistent_result) => match consistent_result {
            GetTransactionCountResult::Ok(count) => count,
            GetTransactionCountResult::Err(error) => {
                return Err(format!(
                    "failed to get transaction count for {:?}, error: {:?}",
                    get_transaction_count_args,
                    error
                ));
            }
        },
        MultiGetTransactionCountResult::Inconsistent(inconsistent_results) => {
            return Err(format!(
                "inconsistent results when retrieving transaction count for {:?}. Received results: {:?}",
                get_transaction_count_args,
                inconsistent_results
            ));
        }
    };

    let nonce = transaction_count;
    ic_cdk::println!("Transaction count: {:?}", nonce);

    let (gas_limit, max_fee_per_gas, max_priority_fee_per_gas) = estimate_transaction_fees().await;

    let function_signature = "transfer(address,uint256)";
    let function_selector = &keccak256(function_signature.as_bytes())[..4];

    let value_as_u64: u64 = amount.to_u64().ok_or("Failed to convert amount to u64")?;
    let value = U256::from(value_as_u64);

    let recipient_address = "0x8Da1867ab5eE5385dc72f5901bC9Bd16F580d157"
        .parse::<Address>()
        .map_err(|e| format!("Failed to parse recipient_address: {}", e))?;

    // Prepare call data
    let mut data = Vec::new();
    data.extend_from_slice(function_selector);
    let recipient_address_bytes = recipient_address.as_bytes();
    data.extend_from_slice(&[0u8; 12]); // Padding
    data.extend_from_slice(recipient_address_bytes);
    let mut amount_bytes = [0u8; 32];
    value.to_big_endian(&mut amount_bytes);
    data.extend_from_slice(&amount_bytes);

    let amount_nat = Nat::from(amount as u128);
    ic_cdk::println!("amount_nat: {:?}", amount_nat);
    let public_key_hex = "02024f9cd747c0ad2ee7978b018d1a78021621429cc3bbc69c6e6a4a49436241b8";

    let public_key_bytes = hex::decode(public_key_hex).expect("Failed to decode public key");
    const EIP1559_TX_ID: u8 = 2;

    let tx = Eip1559TransactionRequest {
        from: None,
        to: Some(H160::from_str(&to).map_err(|e| format!("Invalid 'to' address: {}", e))?.into()),
        gas: Some(gas_limit.into()),
        value: Some(value),
        nonce: Some(nat_to_u256(nonce)),
        data: Default::default(),
        access_list: Default::default(),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas.into()),
        max_fee_per_gas: Some(max_fee_per_gas.into()),
    };

    let mut unsigned_tx_bytes = tx.rlp(chain_id).to_vec();
    unsigned_tx_bytes.insert(0, EIP1559_TX_ID);
    let txhash = keccak256(&unsigned_tx_bytes);
    let (pubkey, signature) = pubkey_and_signature(txhash.to_vec()).await;

    let y_parity = y_parity(&txhash.as_slice(), &signature.signature, &pubkey.public_key);
    ic_cdk::println!("y_parity: {:?}", y_parity);
    
    let signature = ethers_core::types::Signature {
        r: U256::from_big_endian(&signature.signature[0..32]),
        s: U256::from_big_endian(&signature.signature[32..64]),
        v: y_parity as u64,
    };

    let mut signed_tx_bytes = tx.rlp_signed(chain_id, &signature).to_vec();
    signed_tx_bytes.insert(0, EIP1559_TX_ID);

    let signed_tx = format!("0x{}", hex::encode(&signed_tx_bytes));

    // Prepare RPC service
    let custom_rpc_url = "https://eth-sepolia.public.blastapi.io";
    let custom_chain_id = 11155111;
    let custom_rpc_service = RpcApi {
        url: custom_rpc_url.to_string(),
        headers: None,
    };
    let rpc_service = RpcServices::Custom {
        chainId: custom_chain_id,
        services: vec![custom_rpc_service],
    };

    let result = EVM_RPC
    .eth_send_raw_transaction(
        RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
        None,
        signed_tx.clone(),
        20_000_000_000,
    )
    .await
    .map_err(|e| format!("Failed to call eth_sendRawTransaction:"));

let result = match result {
    Ok(res) => (res,),  // This will create a tuple with one element
    Err(e) => return Err(format!("Error")),  // Return early in case of error
};

match result {
    ((MultiSendRawTransactionResult::Consistent(status),),) => match status {
        SendRawTransactionResult::Ok(status) => Ok(evm_rpc_canister_types::SendRawTransactionResult::Ok(status)),
        SendRawTransactionResult::Err(e) => {
            Err(format!("Error: ", ))
        }
    },
    ((MultiSendRawTransactionResult::Inconsistent(_),),) => {
        Err("Status is inconsistent".to_string())
    }
}

}


    // Extract the result
    // match result {
    //     (MultiSendRawTransactionResult::Consistent(send_result),) => {
    //         match send_result {
    //             SendRawTransactionResult::Ok(tx_status) => {
    //                 // Convert SendRawTransactionStatus to String
    //                 Ok(vec![Token::String(format!("{:?}", tx_status))])
    //             },
    //             SendRawTransactionResult::Err(err) => Err(format!("Transaction failed: {:?}", err)),
    //         }
    //     }
    //     (MultiSendRawTransactionResult::Inconsistent(results),) => {
    //         let errors: Vec<String> = results
    //             .into_iter()
    //             .map(|(service, send_result)| match send_result {
    //                 SendRawTransactionResult::Ok(tx_status) => format!("Success with status: {:?}", tx_status),
    //                 SendRawTransactionResult::Err(err) => format!("Service {:?} failed: {:?}", service, err),
    //             })
    //             .collect();
    //         Err(format!("Inconsistent results: {:?}", errors))
    //     }
    // }
    
// }



// #[ic_cdk::update]
// pub async fn send_eth(
//     to: String,
//     amount: f64,
//     dest_chain_id: String,
// ) -> Result<MultiSendRawTransactionResult, std::string::String> {
//     use ethers_core::types::U256;
//     use evm_rpc_canister_types::RpcApi;

//     use num_traits::ToPrimitive;
//     let canister_principal = id();
//     ic_cdk::println!("to: {:?}", to);
//     // Parse the recipient Ethereum address

//     let chain_id: u64 = dest_chain_id
//         .parse::<u64>()
//         .expect("Failed to parse chain ID");

//     let block_tag = BlockTag::Latest; // or other variants like BlockTag::Number(u64), BlockTag::Earliest, etc.
//     let (canister_address, ecdsa_key) = get_network_config(); // Destructure the tuple to get only the address

//     let get_transaction_count_args = GetTransactionCountArgs {
//         address: canister_address.to_string(), //for local
//         block: block_tag,
//     };

//     let get_transaction_count_args_clone = get_transaction_count_args.clone();

//     let transaction_result = EVM_RPC
//         .eth_get_transaction_count(
//             RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
//             None, // Option<RpcConfig>, if you have a specific configuration
//             get_transaction_count_args_clone, // Use the cloned args
//             200_000_000_000_u128, // u128 argument
//         )
//         .await
//         .unwrap_or_else(|e| panic!("failed to get transaction count, error: {:?}", e));

//     // Extract the transaction count from the result
//     let transaction_count = match transaction_result.0 {
//         MultiGetTransactionCountResult::Consistent(consistent_result) => match consistent_result {
//             GetTransactionCountResult::Ok(count) => count,
//             GetTransactionCountResult::Err(error) => {
//                 ic_cdk::trap(&format!(
//                     "failed to get transaction count for {:?}, error: {:?}",
//                     get_transaction_count_args, // Use the original args here
//                     error
//                 ))
//             }
//         },
//         MultiGetTransactionCountResult::Inconsistent(inconsistent_results) => {
//             ic_cdk::trap(&format!(
//                   "inconsistent results when retrieving transaction count for {:?}. Received results: {:?}", 
//                   get_transaction_count_args, // Use the original args here
//                   inconsistent_results
//               ))
//         }
//     };

//     // Convert the transaction count (candid::Nat) to u64
//     let nonce = transaction_count;

//     ic_cdk::println!("Transaction count: {:?}", nonce);

//     // Call a function to estimate transaction fees
//     let (gas_limit, max_fee_per_gas, max_priority_fee_per_gas) = estimate_transaction_fees().await;

//     //for Erc20 token
//     let function_signature = "transfer(address,uint256)";
//     let function_selector = &keccak256(function_signature.as_bytes())[..4];

//     let token = "0x0ec6Ee1D266ee324c58831D690300DC021f205c1";
//     // let to_h160 = H160::from_slice(&hex::decode(to.strip_prefix("0x").unwrap()).unwrap());
//     let value_as_u64: u64 = amount.to_u64().ok_or("Failed to convert Nat to u64")?;
//     let value = U256::from(value_as_u64);

//     let recipient_address = "0x8Da1867ab5eE5385dc72f5901bC9Bd16F580d157"
//         .parse::<Address>()
//         .map_err(|e| format!("Failed to parse recipient_address: {}", e))?;

//     //CallData Generated
//     // Encode the function call data
//     let mut data = Vec::new();
//     data.extend_from_slice(function_selector);

//     // Address parameter (padded to 32 bytes)
//     let recipient_address_bytes = recipient_address.as_bytes();
//     data.extend_from_slice(&[0u8; 12]); // 12 bytes of padding
//     data.extend_from_slice(recipient_address_bytes);

//     // Amount parameter (32 bytes)
//     let mut amount_bytes = [0u8; 32];
//     U256::from(value).to_big_endian(&mut amount_bytes);
//     data.extend_from_slice(&amount_bytes);

//     let amount_nat = Nat::from(amount as u128);

//     ic_cdk::println!("amount_nat , {:?}", amount_nat);
//     let public_key_hex = "02024f9cd747c0ad2ee7978b018d1a78021621429cc3bbc69c6e6a4a49436241b8"; // Your constant public key in hex

//     // Convert the public key hex string into bytes
//     let public_key_bytes = hex::decode(public_key_hex).expect("Failed to decode public key");
//     const EIP1559_TX_ID: u8 = 2;
//     // Create the transaction
//     let tx = Eip1559TransactionRequest {
//         from: None,
//         to: Some(
//             H160::from_str(&to)
//                 .map_err(|e| format!("Invalid 'to' address: {}", e))?
//                 .into(),
//         ),
//         gas: Some(gas_limit.into()),
//         value: Some(value),
//         nonce: Some(nat_to_u256(nonce)),
//         data: Default::default(),
//         access_list: Default::default(),
//         max_priority_fee_per_gas: Some(max_priority_fee_per_gas.into()),
//         max_fee_per_gas: Some(max_fee_per_gas.into()),
//     };


//     let mut unsigned_tx_bytes = tx.rlp(chain_id).to_vec();
//     unsigned_tx_bytes.insert(0, EIP1559_TX_ID);
//     let txhash = keccak256(&unsigned_tx_bytes);

//     let (pubkey, signature) = pubkey_and_signature(txhash.to_vec()).await;

//     let y_parity = y_parity(&txhash.as_slice(), &signature.signature, &pubkey.public_key);
//     ic_cdk::println!("y_parity: {:?}", y_parity);
//     let signature = ethers_core::types::Signature {
//         r: U256::from_big_endian(&signature.signature[0..32]),
//         s: U256::from_big_endian(&signature.signature[32..64]),
//         v: y_parity as u64,
//     };

//     let mut signed_tx_bytes = tx.rlp_signed(chain_id, &signature).to_vec();
//     signed_tx_bytes.insert(0, EIP1559_TX_ID);

//     let signed_tx = format!("0x{}", hex::encode(&signed_tx_bytes));

//     // // Prepare the custom RPC service and chain ID
//     let custom_rpc_url = "https://eth-sepolia.public.blastapi.io";
//     let custom_chain_id = 11155111; // Sepolia's chain ID.
//     let custom_rpc_service = RpcApi {
//         url: custom_rpc_url.to_string(),
//         headers: None, // Optionally set headers if needed
//     };
//     let rpc_service = RpcServices::Custom {
//         chainId: custom_chain_id,
//         services: vec![custom_rpc_service],
//     };

//     let result = EVM_RPC
//         .eth_send_raw_transaction(
//             RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
//             None,
//             signed_tx.clone(),
//             20_000_000_000,
//         )
//         .await
//         .map_err(|e| format!("Failed to call eth_sendRawTransaction: {:?}", e))?;

//     ic_cdk::println!("result , {:?}", result);
//     Ok(result);
// }

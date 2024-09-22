use alloy_primitives::keccak256;
use alloy_primitives::Bytes;
use candid::{Nat, Principal};

use evm_rpc_canister_types::EthSepoliaService;
use evm_rpc_canister_types::HttpOutcallError;
use evm_rpc_canister_types::MultiSendRawTransactionResult;
use evm_rpc_canister_types::RpcServices;
use evm_rpc_canister_types::SendRawTransactionResult;
use evm_rpc_canister_types::{
    BlockTag, EvmRpcCanister, GetTransactionCountArgs, GetTransactionCountResult,
    MultiGetTransactionCountResult,
};

use ic_cdk::id;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{hex, Signature, TxKind};
use ethers_core::types::Address;
use ic_cdk::api::management_canister::ecdsa::{EcdsaCurve, EcdsaKeyId, SignWithEcdsaArgument};

pub const EVM_RPC_CANISTER_ID: Principal =
    Principal::from_slice(b"\x00\x00\x00\x00\x02\x30\x00\xCC\x01\x01"); // 7hfb6-caaaa-aaaar-qadga-cai
pub const EVM_RPC: EvmRpcCanister = EvmRpcCanister(EVM_RPC_CANISTER_ID);

use crate::helper::estimate_transaction_fees;
use crate::helper::get_network_config;
use crate::helper::nat_to_u256;
use crate::helper::nat_to_u64;
use crate::key_pair::PublicKeyStore;

async fn verify(signature_hex: String, message: Vec<u8>) -> Result<bool, String> {
    let public_key_hex = PublicKeyStore::get().ok_or("Public key not found")?;
    ic_cdk::println!("public_key_hex: {:?}", public_key_hex);

    let signature_bytes = hex::decode(signature_hex).expect("failed to hex-decode signature");
    let pubkey_bytes = hex::decode(public_key_hex).expect("failed to hex-decode public key");

    use k256::ecdsa::signature::Verifier;
    let signature = k256::ecdsa::Signature::try_from(signature_bytes.as_slice())
        .expect("failed to deserialize signature");

    ic_cdk::println!("signature verify : {:?}", signature);

    let is_signature_valid = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .expect("failed to deserialize sec1 encoding into public key")
        .verify(&message, &signature)
        .is_ok();

    Ok(is_signature_valid)
}

#[ic_cdk::update]
pub async fn send_eth(
    to: String,
    amount: f64,
    dest_chain_id: String,
) -> Result<MultiSendRawTransactionResult, String> {
    use alloy_eips::eip2718::Encodable2718;
    use ethers_core::types::U256;
    use evm_rpc_canister_types::RpcApi;

    use num_traits::ToPrimitive;
    let canister_principal = id();
    ic_cdk::println!("to: {:?}", to);
    // Parse the recipient Ethereum address

    let chain_id: u64 = dest_chain_id
        .parse::<u64>()
        .expect("Failed to parse chain ID");

    let block_tag = BlockTag::Latest; // or other variants like BlockTag::Number(u64), BlockTag::Earliest, etc.
    let (canister_address, ecdsa_key) = get_network_config(); // Destructure the tuple to get only the address

    let get_transaction_count_args = GetTransactionCountArgs {
        address: canister_address.to_string(), //for local
        block: block_tag,
    };

    let get_transaction_count_args_clone = get_transaction_count_args.clone();

    let transaction_result = EVM_RPC
        .eth_get_transaction_count(
            RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
            None, // Option<RpcConfig>, if you have a specific configuration
            get_transaction_count_args_clone, // Use the cloned args
            200_000_000_000_u128, // u128 argument
        )
        .await
        .unwrap_or_else(|e| panic!("failed to get transaction count, error: {:?}", e));

    // Extract the transaction count from the result
    let transaction_count = match transaction_result.0 {
        MultiGetTransactionCountResult::Consistent(consistent_result) => match consistent_result {
            GetTransactionCountResult::Ok(count) => count,
            GetTransactionCountResult::Err(error) => {
                ic_cdk::trap(&format!(
                    "failed to get transaction count for {:?}, error: {:?}",
                    get_transaction_count_args, // Use the original args here
                    error
                ))
            }
        },
        MultiGetTransactionCountResult::Inconsistent(inconsistent_results) => {
            ic_cdk::trap(&format!(
                  "inconsistent results when retrieving transaction count for {:?}. Received results: {:?}", 
                  get_transaction_count_args, // Use the original args here
                  inconsistent_results
              ))
        }
    };

    // Convert the transaction count (candid::Nat) to u64
    let nonce = nat_to_u64(transaction_count).await;

    ic_cdk::println!("Transaction count: {:?}", nonce);

    // Call a function to estimate transaction fees
    let (gas_limit, max_fee_per_gas, max_priority_fee_per_gas) = estimate_transaction_fees().await;

    //for Erc20 token
    let function_signature = "transfer(address,uint256)";
    let function_selector = &keccak256(function_signature.as_bytes())[..4];

    let token = "0x0ec6Ee1D266ee324c58831D690300DC021f205c1";
    // let to_h160 = H160::from_slice(&hex::decode(to.strip_prefix("0x").unwrap()).unwrap());
    let value_as_u64: u64 = amount.to_u64().ok_or("Failed to convert Nat to u64")?;
    let value = U256::from(value_as_u64);

    let recipient_address = "0x8Da1867ab5eE5385dc72f5901bC9Bd16F580d157"
        .parse::<Address>()
        .map_err(|e| format!("Failed to parse recipient_address: {}", e))?;

    //CallData Generated
    // Encode the function call data
    let mut data = Vec::new();
    data.extend_from_slice(function_selector);

    // Address parameter (padded to 32 bytes)
    let recipient_address_bytes = recipient_address.as_bytes();
    data.extend_from_slice(&[0u8; 12]); // 12 bytes of padding
    data.extend_from_slice(recipient_address_bytes);

    // Amount parameter (32 bytes)
    let mut amount_bytes = [0u8; 32];
    U256::from(value).to_big_endian(&mut amount_bytes);
    data.extend_from_slice(&amount_bytes);

    let amount_nat = Nat::from(amount as u128);

    ic_cdk::println!("amount_nat , {:?}", amount_nat);
    let public_key_hex = "02024f9cd747c0ad2ee7978b018d1a78021621429cc3bbc69c6e6a4a49436241b8"; // Your constant public key in hex

    // Convert the public key hex string into bytes
    let public_key_bytes = hex::decode(public_key_hex).expect("Failed to decode public key");

    // Create the transaction
    let transaction = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        to: TxKind::Call(to.parse().expect("failed to parse recipient address")),
        value: nat_to_u256(amount_nat).await,
        access_list: Default::default(),
        input: Default::default(),
        // input: Bytes::from(data),
    };

    let message_hash = transaction.signature_hash();
    // let message_hash = transaction.signature_hash().0;

    // Define derivation_path and key_id

    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: ecdsa_key.to_string(), // Replace with the actual key ID name
    };

    // Sign the transaction hash

    let canister_id_blob = ic_cdk::id().as_slice().to_vec();

    let (result,) =
        ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(SignWithEcdsaArgument {
            message_hash: message_hash.to_vec(),
            derivation_path: vec![canister_id_blob],
            key_id,
        })
        .await
        .map_err(|e| format!("Failed to sign with ECDSA: {:?}", e))?;

    ic_cdk::println!("result , {:?}", result);

    let signature_hex = hex::encode((result.signature).clone());
    ic_cdk::println!("signature_hex  , {:?}", signature_hex);
    // let resp = verify(signature_hex, message_hash.to_vec().clone()).await;


    let signature_length = result.signature.len();
    let signature = <[u8; 64]>::try_from(result.signature).unwrap_or_else(|_| {
        panic!(
            "BUG: invalid signature from management canister. Expected 64 bytes but got {} bytes",
            signature_length
        )
    });

    ic_cdk::println!("signature  , {:?}", signature);

    let recovery_id_even: u8 = 0; // For even y-coordinate (v = 0)
    let recovery_id_odd: u8 = 1; // For odd y-coordinate (v = 1)

    // Create two signatures: one for even and one for odd y-coordinate
    let signature_even = Signature::from_bytes_and_parity(&signature, false)
        .expect("BUG: failed to create a signature with even y-coordinate");
    let signature_odd = Signature::from_bytes_and_parity(&signature, true)
        .expect("BUG: failed to create a signature with odd y-coordinate");

    // Sign the transaction twice: once with each signatrure
    let signed_tx_even = transaction.clone().into_signed(signature_even);
    let signed_tx_odd = transaction.clone().into_signed(signature_odd);

    // Encode both transactions into raw format
    let mut tx_bytes_even: Vec<u8> = vec![];
    let mut tx_bytes_odd: Vec<u8> = vec![];
    TxEnvelope::from(signed_tx_even).encode_2718(&mut tx_bytes_even);
    TxEnvelope::from(signed_tx_odd).encode_2718(&mut tx_bytes_odd);

    let raw_transaction_hex_even = format!("0x{}", hex::encode(&tx_bytes_even));
    let raw_transaction_hex_odd = format!("0x{}", hex::encode(&tx_bytes_odd));

    ic_cdk::println!(
        "Sending raw transaction hex for even y {}",
        raw_transaction_hex_even
    );
    ic_cdk::println!(
        "Sending raw transaction hex for odd y {}",
        raw_transaction_hex_odd
    );

    // Prepare the custom RPC service and chain ID
    let custom_rpc_url = "https://eth-sepolia.public.blastapi.io";
    let custom_chain_id = 11155111; // Sepolia's chain ID.
    let custom_rpc_service = RpcApi {
        url: custom_rpc_url.to_string(),
        headers: None, // Optionally set headers if needed
    };
    let rpc_service = RpcServices::Custom {
        chainId: custom_chain_id,
        services: vec![custom_rpc_service],
    };

    // Send both transactions using the custom RPC service
    let (result_even,) = EVM_RPC
        .eth_send_raw_transaction(
            rpc_service.clone(),
            None,
            raw_transaction_hex_even.clone(),
            200_000_000_000_u128,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Failed to send raw transaction with even y: {}, error: {:?}",
                raw_transaction_hex_even, e
            )
        });

    ic_cdk::println!("Transaction result for even y: {:?}", result_even);

    let (result_odd,) = EVM_RPC
        .eth_send_raw_transaction(
            rpc_service,
            None,
            raw_transaction_hex_odd.clone(),
            200_000_000_000_u128,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Failed to send raw transaction with odd y: {}, error: {:?}",
                raw_transaction_hex_odd, e
            )
        });

    ic_cdk::println!("Transaction result for odd y: {:?}", result_odd);

    // let recovery_id = RecoveryId::new(/* is_y_odd */ true, /* recid */ true);
    // let recovery_id: u8 = if signature[63] % 2 == 0 { 0 } else { 1 }; // Determine if y-coordinate is odd/even

    // // Use recovery_id to determine if the y-coordinate is odd
    // let is_y_odd = recovery_id == 1; // This checks if recovery_id corresponds to an odd y-coordinate

    // let signature = Signature::from_bytes_and_parity(&signature, is_y_odd)
    //     .expect("BUG: failed to create a signature");

    // ic_cdk::println!("signature , {:?}", signature);

    // let signed_tx = transaction.into_signed(signature);
    // let raw_transaction_hash = *signed_tx.hash();
    // let mut tx_bytes: Vec<u8> = vec![];
    // TxEnvelope::from(signed_tx).encode_2718(&mut tx_bytes);
    // let raw_transaction_hex = format!("0x{}", hex::encode(&tx_bytes));
    // ic_cdk::println!(
    //     "Sending raw transaction hex {} with transaction hash {}",
    //     raw_transaction_hex,
    //     raw_transaction_hash
    // );

    // let raw_transaction_hex = format!("0x{}", hex::encode(&tx_bytes));
    // let custom_rpc_url = "https://eth-sepolia.public.blastapi.io";

    // let custom_chain_id = 11155111; // Sepolia's chain ID.

    // let custom_rpc_service = RpcApi {
    //     url: custom_rpc_url.to_string(),
    //     headers: None, // Optionally set headers if needed
    // };

    // // Definxe the RpcServices using the Custom variant
    // let rpc_service = RpcServices::Custom {
    //     chainId: custom_chain_id,
    //     services: vec![custom_rpc_service],
    // };

    // // Prepare and send the transaction using the custom RPC service.
    // let (result,) = EVM_RPC
    //     .eth_send_raw_transaction(
    //         rpc_service,
    //         None, // You can adjust this depending on other parameters you need.
    //         raw_transaction_hex.clone(),
    //         200_000_000_000_u128,
    //     )
    //     .await
    //     .unwrap_or_else(|e| {
    //         panic!(
    //             "failed to send raw transaction {}, error: {:?}",
    //             raw_transaction_hex, e
    //         )
    //     });

    // match result.clone() {
    //     MultiSendRawTransactionResult::Consistent(status) => match status {
    //         SendRawTransactionResult::Ok(status) => {
    //             ic_cdk::println!("Status code: {:?}", status);
    //             status
    //         }
    //         SendRawTransactionResult::Err(e) => {
    //             ic_cdk::trap(format!("Error: {:?}", e).as_str());
    //         }
    //     },
    //     MultiSendRawTransactionResult::Inconsistent(_) => {
    //         ic_cdk::trap("Status is inconsistent");
    //     }
    // };

    // ic_cdk::println!(
    //         "Result of sending raw transaction {}: {:?}. \
    //     Due to the replicated nature of HTTPs outcalls, an error such as transaction already known or nonce too low could be reported, \
    //     even though the transaction was successfully sent. \
    //     Check whether the transaction appears on Etherscan or check that the transaction count on \
    //     that address at latest block height did increase.",
    //         raw_transaction_hex,
    //         result.clone()
    //     );
    // ic_cdk::println!(
    //     "raw_transaction_hash.to_string() {:?}",
    //     raw_transaction_hash.to_string()
    // );

    // let (result2,) = EVM_RPC
    //     .eth_get_transaction_receipt(
    //         RpcServices::EthSepolia(Some(vec![
    //             EthSepoliaService::Alchemy,
    //             EthSepoliaService::BlockPi,
    //             EthSepoliaService::Ankr,
    //         ])),
    //         None,
    //         raw_transaction_hash.to_string(),
    //         2_000_000_000_u128,
    //     )
    //     .await
    //     .unwrap_or_else(|e| {
    //         panic!(
    //             "failed to get transaction receipt {}, error: {:?}",
    //             raw_transaction_hex, e
    //         )
    //     });

    // ic_cdk::println!("result2 {:?}", result2);

    // let tx_hash_array: [u8; 32] = message_hash.try_into().expect("Expected a 32-byte array");

    // Assuming signature is a Vec<u8> with a length of 65
    // let signature_array: [u8; 64] = signature.try_into().expect("Expected a 64-byte array");

    // let recovery_id = compute_recovery_id(&tx_hash_array, &signature_array);
    // ic_cdk::println!("recovery_id: {:?}", recovery_id);

    Ok(result_odd)
}

// {
//     "chainId": "11155111",
//     "type": "EIP-1559",
//     "valid": true,
//     "hash": "0x10bafb28e4e307618befbe77935604bed1a58c8abf3d1509af8d5ed777d5be3e",
//     "nonce": "23",
//     "gasLimit": "51000",
//     "maxFeePerGas": "50000000000",
//     "maxPriorityFeePerGas": "30000000000",
//     "from": "0x894e7Ad997D33D2B15634ABB2358624aDF05B0e5",
//     "to": "0x8da1867ab5ee5385dc72f5901bc9bd16f580d157",
//     "publicKey": "0x04024f9cd747c0ad2ee7978b018d1a78021621429cc3bbc69c6e6a4a49436241b82775c74f63a273afd6728d368b2cdbe47459133ec7e20be602cbf1e6ec5b3c08",
//     "v": "01",
//     "r": "fc38eaa213c0aaaaf21d48f439908c01419affdc6348875fc1e7bdfca5acccc6",
//     "s": "067fae19c31125071e1c44d2ca60b354581161f6902bfd09c1229c93ac3ccb51",
//     "value": "111",
//     "input": "0x02024f9cd747c0ad2ee7978b018d1a78021621429cc3bbc69c6e6a4a49436241b8",
//     "functionHash": "0x02024f9c",
//     "possibleFunctions": []
//   }

// {
//     "chainId": "11155111",
//     "type": "EIP-1559",
//     "valid": true,
//     "hash": "0x0b2f964a2e1db0acda517d36e549e548d5aa9daa79f3108391f8b2e6842ed348",
//     "nonce": "25",
//     "gasLimit": "51000",
//     "maxFeePerGas": "50000000000",
//     "maxPriorityFeePerGas": "30000000000",
//     "from": "0x894e7Ad997D33D2B15634ABB2358624aDF05B0e5",
//     "to": "0x8da1867ab5ee5385dc72f5901bc9bd16f580d157",
//     "publicKey": "0x04024f9cd747c0ad2ee7978b018d1a78021621429cc3bbc69c6e6a4a49436241b82775c74f63a273afd6728d368b2cdbe47459133ec7e20be602cbf1e6ec5b3c08",
//     "v": "01",
//     "r": "d7ace7ec3747f875114c8fb39ac8c8f3c49baeafee42d170eec7ffe30c879f38",
//     "s": "43fd75a4be8e81d74f40bfc0e0a7c03090873dbfff629ff8072f3fcd3335262b",
//     "value": "111",
//     "input": "0x02024f9cd747c0ad2ee7978b018d1a78021621429cc3bbc69c6e6a4a49436241b8",
//     "functionHash": "0x02024f9c",
//     "possibleFunctions": []
//   }

// If signature[63] % 2 == 0, it typically indicates that the y coordinate of the public key is even, thus setting the parity to 0.
// If signature[63] % 2 != 0, it indicates that the y coordinate is odd, setting the parity to 1.
use alloy_primitives::keccak256;
use candid::{Nat, Principal};

use evm_rpc_canister_types::EthSepoliaService;
use evm_rpc_canister_types::MultiSendRawTransactionResult;
use evm_rpc_canister_types::RpcServices;
use evm_rpc_canister_types::{
    BlockTag, EvmRpcCanister, GetTransactionCountArgs, GetTransactionCountResult,
    MultiGetTransactionCountResult,
};

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{hex, Signature, TxKind};
use ethers_core::types::Address;
use ic_cdk::api::management_canister::ecdsa::{EcdsaCurve, EcdsaKeyId, SignWithEcdsaArgument};
use k256::ecdsa::RecoveryId;

pub const EVM_RPC_CANISTER_ID: Principal =
    Principal::from_slice(b"\x00\x00\x00\x00\x02\x30\x00\xCC\x01\x01"); // 7hfb6-caaaa-aaaar-qadga-cai
pub const EVM_RPC: EvmRpcCanister = EvmRpcCanister(EVM_RPC_CANISTER_ID);

use crate::helper::estimate_transaction_fees;
use crate::helper::nat_to_u256;
use crate::helper::nat_to_u64;

#[ic_cdk::update]
pub async fn send_eth(to: String, amount: f64,dest_chain_id:String) -> Result<MultiSendRawTransactionResult, String> {
    use alloy_eips::eip2718::Encodable2718;
    use num_traits::ToPrimitive;


    use ethers_core::types::U256;
    use evm_rpc_canister_types::RpcApi;

    ic_cdk::println!("to: {:?}", to);
    // Parse the recipient Ethereum address

    let chain_id: u64 = dest_chain_id.parse::<u64>().expect("Failed to parse chain ID");

    let block_tag = BlockTag::Latest; // or other variants like BlockTag::Number(u64), BlockTag::Earliest, etc.

    let get_transaction_count_args = GetTransactionCountArgs {
        // address: "0xB6Db51070abB50a18187c688Ff76E0B0e094FEF8".to_string(), //for local 
        address: "0xb8C7c5Adf5080E15a6a71F57e2d5f4a21AfE8775".to_string(),
        block: block_tag, // Pass the correct BlockTag here
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
        input:Default::default(),
        // input: Bytes::from(data),
    };

    let message_hash = transaction.signature_hash().0;



    // Define derivation_path and key_id
    let derivation_path = vec![]; // Replace with the actual derivation path
    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "test_key_1".to_string(), // Replace with the actual key ID name
    };

    // Sign the transaction hash
    let (result,) =
        ic_cdk::api::management_canister::ecdsa::sign_with_ecdsa(SignWithEcdsaArgument {
            message_hash: message_hash.to_vec(),
            derivation_path,
            key_id,
        })
        .await
        .map_err(|e| format!("Failed to sign with ECDSA: {:?}", e))?;

    let signature_length = result.signature.len();
    let signature = <[u8; 64]>::try_from(result.signature).unwrap_or_else(|_| {
        panic!(
            "BUG: invalid signature from management canister. Expected 64 bytes but got {} bytes",
            signature_length
        )
    });

    let recovery_id = RecoveryId::new(/* is_y_odd */ true, /* recid */ false);

    // You might need to pass the recovery_id into a function that requires it
    // If you're working with a method that expects the `is_y_odd` function, do it like this:
    let is_y_odd = recovery_id.is_y_odd();

    let signature = Signature::from_bytes_and_parity(&signature, is_y_odd)
        .expect("BUG: failed to create a signature");

    ic_cdk::println!("signature , {:?}", signature);

    let signed_tx = transaction.into_signed(signature);
    let raw_transaction_hash = *signed_tx.hash();
    let mut tx_bytes: Vec<u8> = vec![];
    TxEnvelope::from(signed_tx).encode_2718(&mut tx_bytes);
    let raw_transaction_hex = format!("0x{}", hex::encode(&tx_bytes));
    ic_cdk::println!(
        "Sending raw transaction hex {} with transaction hash {}",
        raw_transaction_hex,
        raw_transaction_hash
    );

    // Convert the encoded transaction to a hex string with "0x" prefix
    let raw_transaction_hex = format!("0x{}", hex::encode(&tx_bytes));
    let custom_rpc_url = "https://ethereum-sepolia-rpc.publicnode.com";

    let custom_chain_id = 11155111; // Sepolia's chain ID.

    let custom_rpc_service = RpcApi {
        url: custom_rpc_url.to_string(),
        headers: None, // Optionally set headers if needed
    };

    // Define the RpcServices using the Custom variant
    let rpc_service = RpcServices::Custom {
        chainId: custom_chain_id,
        services: vec![custom_rpc_service],
    };

    // Prepare and send the transaction using the custom RPC service.
    let (result,) = EVM_RPC
        .eth_send_raw_transaction(
            rpc_service,
            None, // You can adjust this depending on other parameters you need.
            raw_transaction_hex.clone(),
            200_000_000_000_u128,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "failed to send raw transaction {}, error: {:?}",
                raw_transaction_hex, e
            )
        });

    // let (result,) = EVM_RPC
    //     .eth_send_raw_transaction(
    //         RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
    //         None,
    //         raw_transaction_hex.clone(),
    //         2_000_000_000_u128,
    //     )
    //     .await
    //     .unwrap_or_else(|e| {
    //         panic!(
    //             "failed to send raw transaction {}, error: {:?}",
    //             raw_transaction_hex, e
    //         )
    //     });

    ic_cdk::println!(
            "Result of sending raw transaction {}: {:?}. \
        Due to the replicated nature of HTTPs outcalls, an error such as transaction already known or nonce too low could be reported, \
        even though the transaction was successfully sent. \
        Check whether the transaction appears on Etherscan or check that the transaction count on \
        that address at latest block height did increase.",
            raw_transaction_hex,
            result
        );
    ic_cdk::println!(
        "raw_transaction_hash.to_string() {:?}",
        raw_transaction_hash.to_string()
    );

    let (result2,) = EVM_RPC
        .eth_get_transaction_receipt(
            RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
            None,
            raw_transaction_hash.to_string(),
            2_000_000_000_u128,
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "failed to get transaction receipt {}, error: {:?}",
                raw_transaction_hex, e
            )
        });

    ic_cdk::println!("result2 {:?}", result2);

    // let tx_hash_array: [u8; 32] = message_hash.try_into().expect("Expected a 32-byte array");

    // Assuming signature is a Vec<u8> with a length of 65
    // let signature_array: [u8; 64] = signature.try_into().expect("Expected a 64-byte array");

    // let recovery_id = compute_recovery_id(&tx_hash_array, &signature_array);
    // ic_cdk::println!("recovery_id: {:?}", recovery_id);

    Ok(result)
}

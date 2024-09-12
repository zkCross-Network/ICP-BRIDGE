use candid::CandidType;
use candid::{Nat, Principal};

use evm_rpc_canister_types::EvmRpcCanister;

use evm_rpc_canister_types::EthSepoliaService;
use evm_rpc_canister_types::RpcServices;
use ic_cdk::api::management_canister::http_request::http_request;
use ic_cdk::api::management_canister::http_request::HttpMethod;
use evm_rpc_canister_types::MultiGetTransactionReceiptResult;
use serde::{Deserialize,Serialize};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

use ic_cdk::api::management_canister::http_request::CanisterHttpRequestArgument;

mod helper;
mod key_pair;
mod send_eth;

pub const EVM_RPC_CANISTER_ID: Principal =
    Principal::from_slice(b"\x00\x00\x00\x00\x02\x30\x00\xCC\x01\x01"); // 7hfb6-caaaa-aaaar-qadga-cai
pub const EVM_RPC: EvmRpcCanister = EvmRpcCanister(EVM_RPC_CANISTER_ID);

pub struct PublicKeyReply {
    pub canister_principal: String,
    pub public_key_hex: String,
    pub ethereum_address: String,
}

//  #[ic_cdk::update]
//  pub async fn get_logs() -> Result<(), String> {
//     use evm_rpc_canister_types::GetLogsArgs;
//     use evm_rpc_canister_types::MultiGetLogsResult;
//     use num_bigint::BigUint;
//     use num_traits::FromPrimitive;

//     use evm_rpc_canister_types::EthSepoliaService;
//     use evm_rpc_canister_types::RpcServices;
//     // let max_range = BigUint::from_u32(300).expect("Failed to create BigUint for range");

//     // Calculate toBlock by adding 500 blocks to fromBlock
//     // let to_block_number = if from_block_number.clone() + &max_range
//     //     > BigUint::from_u32(0xFFFFFFFF).expect("Failed to create BigUint for max block")
//     // {
//     //     BigUint::from_u32(0xFFFFFFFF).expect("Failed to create BigUint for max block")
//     // } else {
//     //     from_block_number.clone() + max_range
//     // };

//     // Define the parameters for the RPC call
//     // toBlock: Some(BlockTag::Number(candid::Nat(to_block_number))), // Replace with the actual ending block if needed

//     let from_block_number =
//         BigUint::from_u32(6631210).expect("Failed to convert integer to BigUint");

//     let to_block_number = BigUint::from_u32(6631240).expect("Failed to convert integer to BigUint");

//     let get_logs_args = GetLogsArgs {
//         fromBlock: Some(BlockTag::Number(candid::Nat(from_block_number))),
//         toBlock: Some(BlockTag::Number(candid::Nat(to_block_number))),

//         addresses: vec!["0x8DE51663Ad75882a203b487403F52AfDE5ab0CA8".to_string()],
//         topics: Some(vec![vec![
//             "0x0c70134544ecb606c925d92ab004750eb59a029d4fe6f11b87accaeefd019162".to_string(),
//             "0x000000000000000000000000e0cc39219a7a726aa98f944551fb91ab6059fd51".to_string(),
//         ]]),
//     };

//     // Define RPC services
//     let rpc_services = RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy]));

//     // Define cycles (or gas) limit
//     let cycles = 5_000_000_000_u128;

//     // Call the RPC method
//     let (result,) = EVM_RPC
//         .eth_get_logs(rpc_services, None, get_logs_args, cycles)
//         .await
//         .map_err(|e| format!("Failed to send raw transaction: {:?}", e))?;

//     // ic_cdk::println!("result: {:?}", result);
//     // Handle the result
//     match result {
//         MultiGetLogsResult::Consistent(logs) => {
//             // Process logs here
//             ic_cdk::println!("Logs: {:?}", logs);
//             Ok(())
//         }
//         MultiGetLogsResult::Inconsistent(_) => {
//             Err("RPC providers gave inconsistent results".into())
//         }
//     }
// }

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct PriceResponse {
    ethereum: Currency,
    arbitrum: Currency,
}

#[derive(CandidType, Deserialize, Serialize, Debug)]
pub struct Currency {
    usd: f64,
}

// Convert candid::Nat to f64
fn nat_to_f64(nat: &Nat) -> Result<f64, String> {
    let big_uint = BigUint::from_bytes_be(&nat.0.to_bytes_le());

    // Convert BigUint to f64
    big_uint.to_f64().ok_or("Failed to convert Nat to f64".into())
}

#[ic_cdk::update]
async fn fetch_crypto_prices_and_calculate_ethereum(amount_nat: f64) -> Result<f64, String> {
    ic_cdk::println!("amount_nat {:?} ", amount_nat);
    // Convert Nat (wei) to Ether (f64)
    let wei_to_eth_factor = 1e18;
    // let amount_of_arbitrum_wei = nat_to_f64(&amount_nat)?;
    // ic_cdk::println!("amount_of_arbitrum_wei {:?} ", amount_of_arbitrum_wei);
    let amount_of_arbitrum = amount_nat / wei_to_eth_factor;
    ic_cdk::println!("amount_of_arbitrum {:?} ", amount_of_arbitrum);

    // Define the URL for the CoinGecko API
    let url = "https://api.coingecko.com/api/v3/simple/price?ids=ethereum,arbitrum&vs_currencies=usd";

    // Define the request headers (if needed)
    let request_headers = vec![];

    let request = CanisterHttpRequestArgument {
        url: url.to_string(),
        max_response_bytes: None,
        method: HttpMethod::GET,
        headers: request_headers,
        body: None,
        transform: None, // Transform can be used if you need to modify the response
    };

    // Make the HTTP request
    let cycles: u128 = 10_000_000;
    let response = match http_request(request, cycles).await {
        Ok((response,)) => response,
        Err((r, m)) => return Err(format!("HTTP request failed: RejectionCode: {r:?}, Error: {m}")),
    };

    // Convert response body to a string
    let response_body = String::from_utf8(response.body)
        .map_err(|e| format!("Failed to decode response body: {}", e))?;

    // Parse the JSON response
    let json_response: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|e| format!("Failed to parse JSON response: {}", e))?;

    // Extract prices from the JSON response
    let arbitrum_usd_price = json_response["arbitrum"]["usd"]
        .as_f64()
        .ok_or("Failed to get Arbitrum USD price")?;
    let ethereum_usd_price = json_response["ethereum"]["usd"]
        .as_f64()
        .ok_or("Failed to get Ethereum USD price")?;

    // Calculate the value of the provided amount of Arbitrum in Ethereum
    let value_in_ethereum = (amount_of_arbitrum * arbitrum_usd_price) / ethereum_usd_price;

  // Convert value_in_ethereum (ETH) back to wei
  let value_in_ethereum_wei = value_in_ethereum * wei_to_eth_factor;
//   let value_in_ethereum_nat = Nat::from(value_in_ethereum_wei as u128);

  // Print the result
  ic_cdk::println!(
      "Amount of Ethereum equivalent to {} ",
      value_in_ethereum_wei
  );

  // Return the result in Wei
  Ok(value_in_ethereum_wei)
}

#[ic_cdk::update]
pub async fn verify_trans(
    txn: String,
    to: String,
    amount: String,
    dest_chain_id:String
) -> Result<MultiGetTransactionReceiptResult, String> {
    ic_cdk::println!("verify_trans {:?},amount{:?} ,dest_chain_id {:?}", txn,amount,dest_chain_id);
    


    use std::str::FromStr;
    let amount_nat =
        f64::from_str(&amount).map_err(|e| format!("Failed to convert amount to Nat: {:?}", e))?;
        let release_eth = fetch_crypto_prices_and_calculate_ethereum(amount_nat).await;
        ic_cdk::println!("release_eth {:?}", release_eth);



        let result = send_eth::send_eth(to, release_eth?,dest_chain_id).await;

    use crate::MultiGetTransactionReceiptResult::Consistent;
    use evm_rpc_canister_types::GetTransactionReceiptResult;
    use evm_rpc_canister_types::TransactionReceipt;
    let (result2,) = EVM_RPC
        .eth_get_transaction_receipt(
            RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
            None,
            txn.clone(),
            2_000_000_000_u128,
        )
        .await
        .map_err(|e| format!("failed to get transaction receipt {}, error: {:?}", txn, e))?;

    ic_cdk::println!("result2 {:?}", result2);
    match result2.clone() {
        Consistent(GetTransactionReceiptResult::Ok(Some(TransactionReceipt {
            status, ..
        }))) => {
            ic_cdk::println!("Transaction status: {:?}", status);
           
            // ic_cdk::println!("Transaction result: {:?}", result);
        }
        _ => ic_cdk::println!("Unexpected result"),
    }

    //

    Ok(result2)
}





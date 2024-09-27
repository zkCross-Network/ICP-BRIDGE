use ethers_core::types::U256;
use alloy_primitives::Uint;
use num_bigint::BigUint;

use candid::{Nat, Principal};
use evm_rpc_canister_types::EthSepoliaService;
use evm_rpc_canister_types::EvmRpcCanister;

use evm_rpc_canister_types::{
    BlockTag, GetTransactionCountArgs, GetTransactionCountResult, MultiGetTransactionCountResult,
};

use evm_rpc_canister_types::RpcServices;
pub const EVM_RPC_CANISTER_ID: Principal =
    Principal::from_slice(b"\x00\x00\x00\x00\x02\x30\x00\xCC\x01\x01"); // 7hfb6-caaaa-aaaar-qadga-cai
pub const EVM_RPC: EvmRpcCanister = EvmRpcCanister(EVM_RPC_CANISTER_ID);

const NETWORK: &str = "local";
pub fn get_network_config() -> (&'static str, &'static str) {
    match NETWORK {
        "local" => (
            "0x6148F683f52Ae3118Fb221943758f4870f88a804", // address_local
            "dfx_test_key",                               // ecdsa_key_local
        ),
        "mainnet" => (
            "0xA2750976d1Ec8FF2c8Aeb0e46a9df6053e569931", // address_main
            "test_key_1",                                 // ecdsa_key_main
        ),
        _ => panic!("Unknown network!"),
    }
}

pub async fn nat_to_u64(nat: Nat) -> u64 {
    use num_traits::cast::ToPrimitive;
    nat.0
        .to_u64()
        .unwrap_or_else(|| ic_cdk::trap(&format!("Nat {} doesn't fit into a u64", nat)))
}

pub async fn estimate_transaction_fees() -> (u128, u128, u128) {
    const GAS_LIMIT: u128 = 51_000; // Gas limit
    const MAX_FEE_PER_GAS: u128 = 30_000_000_000; // Updated max fee per gas to include priority fee
    const MAX_PRIORITY_FEE_PER_GAS: u128 = 10_000_000_000; // Max priority fee per gas

    (GAS_LIMIT, MAX_FEE_PER_GAS, MAX_PRIORITY_FEE_PER_GAS)
}


pub fn nat_to_u256(value: Nat) -> U256 {
    let value_bytes = value.0.to_bytes_be();
    assert!(
        value_bytes.len() <= 32,
        "Nat does not fit in a U256: {}",
        value
    );
    let mut value_u256 = [0u8; 32];
    value_u256[32 - value_bytes.len()..].copy_from_slice(&value_bytes);
    
    // Convert alloy_primitives::Uint<256, 4> to ethers_core::types::U256
    U256::from_big_endian(&value_u256)
}


pub async fn get_transaction_count() -> u64 {
    let block_tag = BlockTag::Latest; // or other variants like BlockTag::Number(u64), BlockTag::Earliest, etc.

    let get_transaction_count_args = GetTransactionCountArgs {
        address: "0xB6Db51070abB50a18187c688Ff76E0B0e094FEF8".to_string(),
        block: block_tag, // Pass the correct BlockTag here
    };

    let get_transaction_count_args_clone = get_transaction_count_args.clone();

    let transaction_result = EVM_RPC
        .eth_get_transaction_count(
            RpcServices::EthSepolia(Some(vec![EthSepoliaService::Alchemy])),
            None, // Option<RpcConfig>, if you have a specific configuration
            get_transaction_count_args_clone, // Use the cloned args
            2_000_000_000_u128, // u128 argument
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

    nat_to_u64(transaction_count).await
}

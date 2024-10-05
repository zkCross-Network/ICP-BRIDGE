const NETWORK: &str = "mainnet";

pub fn get_network_config() -> (&'static str, &'static str) {
    match NETWORK {
        "local" => (
            "0xaE9CB8bD93D8ca15AD56470848905fF32195b71A", // address_local
            "dfx_test_key",                               // ecdsa_key_local
        ),
        "mainnet" => (
            "0xA2750976d1Ec8FF2c8Aeb0e46a9df6053e569931", // address_main
            "test_key_1",                                 // ecdsa_key_main
        ),
        _ => panic!("Unknown network!"),
    }
}
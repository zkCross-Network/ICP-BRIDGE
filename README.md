# ICP-BRIDGE
Interchain Decentralised Bridge using ICP as source chain.

Cross Chain Bridge
Arbitrum -> Ethereum 

1) Start you centralised indexer (locally) 
```npm start```
It is used to catch the event when the lock is called and catch the event from the evm deployed contract will get all information about in_amount , dest_chain_id , destination_address and after catch event correct will call the sign_backend canister with the argument of txn_hash , in_amount, destination_address .

2) Start the icp by using 
```dfx start```

3) Deployed all canister using 
```dfx deploy ```

(Note): Replace the canister id (when you deploy the canisters) and the host (received when use dfx start ) inside your index.js file of centralised indexer

You will get the sign_backend url , with following functions:-

1) generate_key_pair()
 It is used to generated the key pair for your canister and for that public key internally call the function which will use to get the address for you canister .


2) fetch_crypto_prices_and_calculate_ethereum()
It is used to get the (Eth) amount user will get in return of the arbitrum of user locked .

3) verify_trans()
It is used to verify the txn , if it is valid or not which will be called from the centralised indexer and if the txn is valid then on success valid txn it will call the send_eth function internally.

4) send_eth()
It is used to send the amount of eth from the canister address to the destination user address by making the txn using TxnEip1559 , which  will sign this txn with the ecdsa and will send this signed txn to the eth_send_raw_transaction() .

(Notes:-)

For local inside ecdsa signing
Use key -> `test_key_1 `

For Mainnet 
Use  key -> `test_key_1` or `key_1`

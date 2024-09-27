import * as web3 from "./web3.js";
import { HttpAgent } from "@dfinity/agent";

import {
  canisterId,
  createActor,
} from "../declarations/sign_backend/index.js";
import { Ed25519KeyIdentity } from "@dfinity/identity";

const evmBlockScanner = async () => {
  try {
    const identity = Ed25519KeyIdentity.generate(
      new Uint8Array(Array.from({ length: 32 }).fill(0))
    );

    console.log("idenityt", identity.getPrincipal().toString());

    const canisterId = "br5f7-7uaaa-aaaaa-qaaca-cai";
    // const canisterId="5qtxp-vyaaa-aaaap-qh5rq-cai";

    const signBackend = createActor(canisterId, {
      agentOptions: {
        identity,
        host: "http://127.0.0.1:8080",  
        // host :"https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=5qtxp-vyaaa-aaaap-qh5rq-cai",
      },
    });

    console.log("signBackend", signBackend);
    //recheck missed Lock Events on common contract
    //   console.log("Gettings logs for evmBLockScanner: ", network);
    const fromBlockNumber = 82685375;

    //   const fromBlockNumber = await redis.getLastSyncBlockNumber(
    //     network,
    //     config.events.evm
    //   );
    console.log("From Block: ", fromBlockNumber);
    const toBlockNumber = await web3.getLatestBlockNumber();
    console.log("To block: ", toBlockNumber);

    const contract = await web3.getcontractInstance();
    const filter = contract.filters["TokenTransferred"]?.();
    console.log("Filter: ", filter);
    const logs = await web3.getLogs(
      contract,
      filter,
      fromBlockNumber,
      toBlockNumber
    );
    console.log("Logs got from event: ", logs);
    let transac;
    let des;
    let amount;
    let dest_chain_id;
    for (const log of logs) {
      const parsedLog =  contract.interface.parseLog(log);
      console.log("parsedLog: ", parsedLog);
      amount = parsedLog.args.amount.toString();
      des = parsedLog.args.des_to;
      dest_chain_id = parsedLog.args.dest_chain_id.toString()
      console.log("Transaction Hash: ", log.transactionHash);
      transac = log.transactionHash;
    }

    const result = await signBackend.verify_trans(transac, des, amount,dest_chain_id);
    console.log("Signed backend", result.Ok);
    // for (const log of logs) {
    //   const parsedLog = contract.interface.parseLog(log);
    //   console.log("Parsed Logs: ", parsedLog);
    //   // await saveLockEvent(network, log, parsedLog);
    //   // await redis.setLastSyncBlockNumber(
    //   //   network,
    //   //   config.events.evm,
    //   //   toBlockNumber
    //   // );
    //   console.log("logs saved");
    // }
  } catch (e) {
    console.log("Error in blockscanner: ", e);
    console.log("Starting evmBlockScanner");
    // evmBlockScanner();
    // loggers.logger.error(`🚫 | error in EVM block Scanner`, e.message);
  }
};

evmBlockScanner();

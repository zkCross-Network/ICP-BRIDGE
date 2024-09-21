import { ethers } from "ethers";
import abi from "./abi.json" with {type:'json'};
import * as alchemy from "alchemy-sdk";
 
// export const parseUnits = (amount, decimal) => {
//   const parsedAmount = ethers.utils.parseUnits(amount, decimal);
//   return parsedAmount;
// };
 export const getProvider = () => {
  const rpc = "https://sepolia-rollup.arbitrum.io/rpc";

  let provider = new ethers.providers.JsonRpcProvider(rpc);

  return provider;
};

// export const getWallet = () => {
//   const pk = "6d35c1bdf469031cfe3cbaddd57ca69a36835a39c2a6f2cefc17c804851b0635";
//   const provider = getProvider();
//   const wallet = new ethers.Wallet(pk, provider);
//   return wallet;
// };

export const gettokenAndAddress = () => {
  // 
  let address="0x054b0D625d936ee0B172c73926A1D517Da7d2197";
  // let address = "0xFaFCeF66155B0140AFaa2987Bbecf16D38125FdE"; -> local 
  let token = "0xbacef2640862B42eECcFeAb9Bf750476aE7decc6";
  //lock token 

  return { address, token };
};

export const getcontractInstance = async (network, tokenSymbol) => {
  // const address = config.evmChainsInfo[network]!.address;
  let provider = getProvider();
  const { address, token } = gettokenAndAddress(network, tokenSymbol);


  let contract = new ethers.Contract(address, abi, provider);

  console.log("contact",contract);

  return contract;
};

// export const getErc20contractInstance = (network) => {
//   // const address = config.evmChainsInfo[network]!.address;
//   const wallet = getWallet(network);
//   // console.log("token", token);
//   const contractAbi = getcontractAbi("token");
//   // const contract = new ethers.Contract(address, contractAbi, provider);
//   const midTokenAddress = config.evmChainsInfo[network].supportedTokens.find(
//     (token) => token.symbol.toLowerCase() == "usdt"
//   )?.address;
//   const contract = new ethers.Contract(midTokenAddress, contractAbi, wallet);
//   return contract;
// };

export const getAlchemyNetwork = () => {
  // return "https://eth-sepolia.g.alchemy.com/v2/liRjjrRhM85if04BYb8eGpagn7m7vTJl";
  //   switch (network) {
  //     // case "eth":
  return alchemy.Network.ETH_SEPOLIA;
  //     case "poly":
  //       return alchemy.Network.MATIC_MAINNET;
  //     case "arb":
  //       return alchemy.Network.ARB_MAINNET;
  //     default:
  //       return undefined;
  //   }
};

export const getAlchemySDK = (network) => {
  const alchemyNetwork = getAlchemyNetwork();
  if (!alchemyNetwork) {
    return undefined;
  }
  const sdk = new alchemy.Alchemy({
    network: alchemyNetwork,
    apiKey: "liRjjrRhM85if04BYb8eGpagn7m7vTJl",
  });
  return sdk;
};

// export const contractInterface = new ethers.utils.Interface(abis.spsSwidgeAbi);

export const getLogs = async (
  contract,
  filter,
  fromBlock,
  toBlock
) => {
  const interval = 1000;
  const provider = contract.provider;
  const allLogs = [];
  for (let i = fromBlock; i < toBlock; i += interval) {
    const logs = await provider.getLogs({
      ...filter,
      fromBlock: i,
      toBlock: i + interval,
    });
    // console.log("logs: ", logs)
    allLogs.push(...logs);
  }
  return allLogs;
};

export const getLatestBlockNumber = async (network) => {
  const provider = getProvider();
  const blockNumber = await provider.getBlockNumber();
  return blockNumber;
};

export const getBlockTimestamp = async ( blockNumber) => {
  const provider = getProvider();
  const block = await provider.getBlock(blockNumber);
  return block.timestamp;
};

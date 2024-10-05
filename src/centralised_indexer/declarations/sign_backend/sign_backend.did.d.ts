import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type EthMainnetService = { 'Alchemy' : null } |
  { 'BlockPi' : null } |
  { 'Cloudflare' : null } |
  { 'PublicNode' : null } |
  { 'Ankr' : null };
export type GetTransactionReceiptResult = { 'Ok' : [] | [TransactionReceipt] } |
  { 'Err' : RpcError };
export interface HttpHeader { 'value' : string, 'name' : string }
export type HttpOutcallError = {
    'IcError' : { 'code' : RejectionCode, 'message' : string }
  } |
  {
    'InvalidHttpJsonRpcResponse' : {
      'status' : number,
      'body' : string,
      'parsingError' : [] | [string],
    }
  };
export interface JsonRpcError { 'code' : bigint, 'message' : string }
export type L2MainnetService = { 'Alchemy' : null } |
  { 'BlockPi' : null } |
  { 'PublicNode' : null } |
  { 'Ankr' : null };
export interface LogEntry {
  'transactionHash' : [] | [string],
  'blockNumber' : [] | [bigint],
  'data' : string,
  'blockHash' : [] | [string],
  'transactionIndex' : [] | [bigint],
  'topics' : Array<string>,
  'address' : string,
  'logIndex' : [] | [bigint],
  'removed' : boolean,
}
export type MultiGetTransactionReceiptResult = {
    'Consistent' : GetTransactionReceiptResult
  } |
  { 'Inconsistent' : Array<[RpcService, GetTransactionReceiptResult]> };
export type ProviderError = {
    'TooFewCycles' : { 'expected' : bigint, 'received' : bigint }
  } |
  { 'MissingRequiredProvider' : null } |
  { 'ProviderNotFound' : null } |
  { 'NoPermission' : null };
export type RejectionCode = { 'NoError' : null } |
  { 'CanisterError' : null } |
  { 'SysTransient' : null } |
  { 'DestinationInvalid' : null } |
  { 'Unknown' : null } |
  { 'SysFatal' : null } |
  { 'CanisterReject' : null };
export type Result = { 'Ok' : number } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : string } |
  { 'Err' : string };
export type Result_2 = { 'Ok' : SendRawTransactionResult } |
  { 'Err' : string };
export type Result_3 = { 'Ok' : MultiGetTransactionReceiptResult } |
  { 'Err' : string };
export interface RpcApi { 'url' : string, 'headers' : [] | [Array<HttpHeader>] }
export type RpcError = { 'JsonRpcError' : JsonRpcError } |
  { 'ProviderError' : ProviderError } |
  { 'ValidationError' : ValidationError } |
  { 'HttpOutcallError' : HttpOutcallError };
export type RpcService = { 'EthSepolia' : L2MainnetService } |
  { 'BaseMainnet' : L2MainnetService } |
  { 'Custom' : RpcApi } |
  { 'OptimismMainnet' : L2MainnetService } |
  { 'ArbitrumOne' : L2MainnetService } |
  { 'EthMainnet' : EthMainnetService } |
  { 'Chain' : bigint } |
  { 'Provider' : bigint };
export type SendRawTransactionResult = { 'Ok' : SendRawTransactionStatus } |
  { 'Err' : RpcError };
export type SendRawTransactionStatus = { 'Ok' : [] | [string] } |
  { 'NonceTooLow' : null } |
  { 'NonceTooHigh' : null } |
  { 'InsufficientFunds' : null };
export interface TransactionReceipt {
  'to' : string,
  'status' : bigint,
  'transactionHash' : string,
  'blockNumber' : bigint,
  'from' : string,
  'logs' : Array<LogEntry>,
  'blockHash' : string,
  'type' : string,
  'transactionIndex' : bigint,
  'effectiveGasPrice' : bigint,
  'logsBloom' : string,
  'contractAddress' : [] | [string],
  'gasUsed' : bigint,
}
export type ValidationError = { 'CredentialPathNotAllowed' : null } |
  { 'HostNotAllowed' : string } |
  { 'CredentialHeaderNotAllowed' : null } |
  { 'UrlParseError' : string } |
  { 'Custom' : string } |
  { 'InvalidHex' : string };
export interface _SERVICE {
  'fetch_crypto_prices_and_calculate_ethereum' : ActorMethod<[number], Result>,
  'generate_key_pair' : ActorMethod<[], Result_1>,
  'send_eth' : ActorMethod<[string, number, string], Result_2>,
  'verify_trans' : ActorMethod<[string, string, string, string], Result_3>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];

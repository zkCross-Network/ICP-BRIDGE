export const idlFactory = ({ IDL }) => {
  const Result = IDL.Variant({ 'Ok' : IDL.Float64, 'Err' : IDL.Text });
  const Result_1 = IDL.Variant({ 'Ok' : IDL.Text, 'Err' : IDL.Text });
  const SendRawTransactionStatus = IDL.Variant({
    'Ok' : IDL.Opt(IDL.Text),
    'NonceTooLow' : IDL.Null,
    'NonceTooHigh' : IDL.Null,
    'InsufficientFunds' : IDL.Null,
  });
  const JsonRpcError = IDL.Record({ 'code' : IDL.Int64, 'message' : IDL.Text });
  const ProviderError = IDL.Variant({
    'TooFewCycles' : IDL.Record({ 'expected' : IDL.Nat, 'received' : IDL.Nat }),
    'MissingRequiredProvider' : IDL.Null,
    'ProviderNotFound' : IDL.Null,
    'NoPermission' : IDL.Null,
  });
  const ValidationError = IDL.Variant({
    'CredentialPathNotAllowed' : IDL.Null,
    'HostNotAllowed' : IDL.Text,
    'CredentialHeaderNotAllowed' : IDL.Null,
    'UrlParseError' : IDL.Text,
    'Custom' : IDL.Text,
    'InvalidHex' : IDL.Text,
  });
  const RejectionCode = IDL.Variant({
    'NoError' : IDL.Null,
    'CanisterError' : IDL.Null,
    'SysTransient' : IDL.Null,
    'DestinationInvalid' : IDL.Null,
    'Unknown' : IDL.Null,
    'SysFatal' : IDL.Null,
    'CanisterReject' : IDL.Null,
  });
  const HttpOutcallError = IDL.Variant({
    'IcError' : IDL.Record({ 'code' : RejectionCode, 'message' : IDL.Text }),
    'InvalidHttpJsonRpcResponse' : IDL.Record({
      'status' : IDL.Nat16,
      'body' : IDL.Text,
      'parsingError' : IDL.Opt(IDL.Text),
    }),
  });
  const RpcError = IDL.Variant({
    'JsonRpcError' : JsonRpcError,
    'ProviderError' : ProviderError,
    'ValidationError' : ValidationError,
    'HttpOutcallError' : HttpOutcallError,
  });
  const SendRawTransactionResult = IDL.Variant({
    'Ok' : SendRawTransactionStatus,
    'Err' : RpcError,
  });
  const Result_2 = IDL.Variant({
    'Ok' : SendRawTransactionResult,
    'Err' : IDL.Text,
  });
  const LogEntry = IDL.Record({
    'transactionHash' : IDL.Opt(IDL.Text),
    'blockNumber' : IDL.Opt(IDL.Nat),
    'data' : IDL.Text,
    'blockHash' : IDL.Opt(IDL.Text),
    'transactionIndex' : IDL.Opt(IDL.Nat),
    'topics' : IDL.Vec(IDL.Text),
    'address' : IDL.Text,
    'logIndex' : IDL.Opt(IDL.Nat),
    'removed' : IDL.Bool,
  });
  const TransactionReceipt = IDL.Record({
    'to' : IDL.Text,
    'status' : IDL.Nat,
    'transactionHash' : IDL.Text,
    'blockNumber' : IDL.Nat,
    'from' : IDL.Text,
    'logs' : IDL.Vec(LogEntry),
    'blockHash' : IDL.Text,
    'type' : IDL.Text,
    'transactionIndex' : IDL.Nat,
    'effectiveGasPrice' : IDL.Nat,
    'logsBloom' : IDL.Text,
    'contractAddress' : IDL.Opt(IDL.Text),
    'gasUsed' : IDL.Nat,
  });
  const GetTransactionReceiptResult = IDL.Variant({
    'Ok' : IDL.Opt(TransactionReceipt),
    'Err' : RpcError,
  });
  const L2MainnetService = IDL.Variant({
    'Alchemy' : IDL.Null,
    'BlockPi' : IDL.Null,
    'PublicNode' : IDL.Null,
    'Ankr' : IDL.Null,
  });
  const HttpHeader = IDL.Record({ 'value' : IDL.Text, 'name' : IDL.Text });
  const RpcApi = IDL.Record({
    'url' : IDL.Text,
    'headers' : IDL.Opt(IDL.Vec(HttpHeader)),
  });
  const EthMainnetService = IDL.Variant({
    'Alchemy' : IDL.Null,
    'BlockPi' : IDL.Null,
    'Cloudflare' : IDL.Null,
    'PublicNode' : IDL.Null,
    'Ankr' : IDL.Null,
  });
  const RpcService = IDL.Variant({
    'EthSepolia' : L2MainnetService,
    'BaseMainnet' : L2MainnetService,
    'Custom' : RpcApi,
    'OptimismMainnet' : L2MainnetService,
    'ArbitrumOne' : L2MainnetService,
    'EthMainnet' : EthMainnetService,
    'Chain' : IDL.Nat64,
    'Provider' : IDL.Nat64,
  });
  const MultiGetTransactionReceiptResult = IDL.Variant({
    'Consistent' : GetTransactionReceiptResult,
    'Inconsistent' : IDL.Vec(
      IDL.Tuple(RpcService, GetTransactionReceiptResult)
    ),
  });
  const Result_3 = IDL.Variant({
    'Ok' : MultiGetTransactionReceiptResult,
    'Err' : IDL.Text,
  });
  return IDL.Service({
    'fetch_crypto_prices_and_calculate_ethereum' : IDL.Func(
        [IDL.Float64],
        [Result],
        [],
      ),
    'generate_key_pair' : IDL.Func([], [Result_1], []),
    'send_eth' : IDL.Func([IDL.Text, IDL.Float64, IDL.Text], [Result_2], []),
    'verify_trans' : IDL.Func(
        [IDL.Text, IDL.Text, IDL.Text, IDL.Text],
        [Result_3],
        [],
      ),
  });
};
export const init = ({ IDL }) => { return []; };

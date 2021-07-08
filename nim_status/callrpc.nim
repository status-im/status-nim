import web3, json, strutils
import chronos, json_rpc/client
import settings

type Web3Error* = object of CatchableError

# remoteMethods contains methods that should be routed to
# the upstream node; the rest is considered to be routed to
# the local node.
type RemoteMethod* {.pure.} = enum
  eth_protocolVersion = "eth_protocolVersion",
  eth_syncing = "eth_syncing",
  eth_coinbase = "eth_coinbase",
  eth_mining = "eth_mining",
  eth_hashrate = "eth_hashrate",
  eth_gasPrice = "eth_gasPrice",
  # eth_accounts = "eth_accounts" # due to sub-accounts handling
  eth_blockNumber = "eth_blockNumber",
  eth_getBalance = "eth_getBalance",
  eth_getStorageAt = "eth_getStorageAt",
  eth_getTransactionCount = "eth_getTransactionCount",
  eth_getBlockTransactionCountByHash = "eth_getBlockTransactionCountByHash"
  eth_getBlockTransactionCountByNumber = "eth_getBlockTransactionCountByNumber",
  eth_getUncleCountByBlockHash = "eth_getUncleCountByBlockHash",
  eth_getUncleCountByBlockNumber = "eth_getUncleCountByBlockNumber",
  eth_getCode = "eth_getCode",
  # eth_sign = "eth_sign" # only the local node has an injected account to sign the payload with
  # eth_sendTransaction = "eth_sendTransaction" # we handle this specially calling eth_estimateGas, signing it locally and sending eth_sendRawTransaction afterwards
  eth_sendRawTransaction = "eth_sendRawTransaction",
  eth_call = "eth_call",
  eth_estimateGas = "eth_estimateGas",
  eth_getBlockByHash = "eth_getBlockByHash",
  eth_getBlockByNumber = "eth_getBlockByNumber",
  eth_getTransactionByHash = "eth_getTransactionByHash",
  eth_getTransactionByBlockHashAndIndex = "eth_getTransactionByBlockHashAndIndex",
  eth_getTransactionByBlockNumberAndIndex = "eth_getTransactionByBlockNumberAndIndex",
  eth_getTransactionReceipt = "eth_getTransactionReceipt",
  eth_getUncleByBlockHashAndIndex = "eth_getUncleByBlockHashAndIndex",
  eth_getUncleByBlockNumberAndIndex = "eth_getUncleByBlockNumberAndIndex",
  # eth_getCompilers = "eth_getCompilers"    # goes to the local because there's no need to send it anywhere
  # eth_compileLLL = "eth_compileLLL"      # goes to the local because there's no need to send it anywhere
  # eth_compileSolidity = "eth_compileSolidity" # goes to the local because there's no need to send it anywhere
  # eth_compileSerpent = "eth_compileSerpent"  # goes to the local because there's no need to send it anywhere
  eth_getLogs = "eth_getLogs",
  eth_getWork = "eth_getWork",
  eth_submitWork = "eth_submitWork",
  eth_submitHashrate = "eth_submitHashrate",
  net_version = "net_version",
  net_peerCount = "net_peerCount",
  net_listening = "net_listening"


proc newWeb3*(settings: Settings): Web3 =
  let network = settings.getNetwork()
  if network.isNone:
    raise (ref Web3Error)(msg: "config not found for network " & settings.currentNetwork)

  if not network.get().config.upstreamConfig.enabled:
    raise (ref Web3Error)(msg: "network " & settings.currentNetwork & " is not enabled")

  result = waitFor newWeb3(network.get().config.upstreamConfig.url)

proc callRPC*(web3Conn: Web3, rpcMethod: RemoteMethod, params: JsonNode): Response =
  try:
    result = waitFor web3Conn.provider.call($rpcMethod, params)
  except ValueError:
    raise (ref Web3Error)(msg: getCurrentExceptionMsg())


proc callRPC*(web3Conn: Web3, rpcMethod: string, params: JsonNode): Response =
  if web3Conn == nil:
    raise (ref Web3Error)(msg: "web3 connection is not available")

  try:
    discard parseEnum[RemoteMethod](rpcMethod)
  except:
    return %* {"code": -32601, "message": "the method " & rpcMethod & " does not exist/is not available"}

  try:
    result = waitFor web3Conn.provider.call(rpcMethod, params)
  except ValueError:
    raise (ref Web3Error)(msg: getCurrentExceptionMsg())

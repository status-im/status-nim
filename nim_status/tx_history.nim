import callrpc, conversions, os

import web3, json, strutils, strformat, sequtils
import json_rpc/client
import nimcrypto
import sets
import tables
import rlocks
import # vendor libs
  web3/conversions as web3_conversions, web3/ethtypes,
  sqlcipher, json_serialization, json_serialization/[reader, writer, lexer],
  stew/byteutils

import tx_history/types

#import # nim-status libs
  #../[settings, database, conversions, tx_history, callrpc]
  #
  #
const txsPerPage = 20
const ethTransferType = "eth"
const erc20TransferType = "erc20"

var web3Obj {.threadvar.}: Web3
var db {.threadvar.}: DbConn

proc setWeb3Obj*(web3: Web3) =
  web3Obj = web3

proc setDbConn*(dbConn: DbConn) =
  db = dbConn

# blockNumber can be either "earliest", "latest", "pending", or hex-encoding int
proc getValueForBlock*(address: types.Address, blockNumber: string, methodName: RemoteMethod): int =

  let jsonNode = parseJson(fmt"""["{address}", "{blockNumber}"]""")
  let resp = callRPC(web3Obj, methodName, jsonNode)
  let txCount = fromHex[int](resp.getStr)

  return txCount

proc getLastBlockNumber*(): int =
  var jsonNode = parseJSON("""[]""")
  var resp = callRPC(web3Obj, RemoteMethod.eth_blockNumber, jsonNode)
  return fromHex[int](resp.getStr)

# Find lowest block number for which a condition
# procPtr(address, blockNumber) >= targetValue holds
proc findLowestBlockNumber*(address: types.Address,
                           blockRange: BlockRange,
                           methodName: RemoteMethod, targetValue: int): int =
  var fromBlock = blockRange[0]
  var toBlock = blockRange[1]
  var blockNumber = fromBlock
  while toBlock != fromBlock:
    blockNumber = (toBlock + fromBlock) /% 2
    let blockNumberHex: string = intToHex(blockNumber)
    let value = getValueForBlock(address, blockNumberHex, methodName)
    if value >= targetValue:
      toBlock = blockNumber
    else:
      fromBlock = blockNumber + 1

  result = fromBlock

# Find a block range with minimum txsPerPage transactions
proc txBinarySearch*(address: types.Address, toBlock: int): BlockRange =
  let totalTxCount = getValueForBlock(address, intToHex(toBlock), RemoteMethod.eth_getTransactionCount)
  if totalTxCount == 0:
    return [0, 0]

  var leftBlock = 0
  if totalTxCount > txsPerPage:
    # Find lower bound (number of the block containing lowerTxBound txs
    # This means finding lowest block number containing lowerTxBound txs
    let lowerTxBound = totalTxCount - 19
    leftBlock = findLowestBlockNumber(address, [0, toBlock],
                          RemoteMethod.eth_getTransactionCount, lowerTxBound)
  #else:
    # No need to restrict block range, as there can be incoming transactions
    # anywhere inside the whole range

  return [leftBlock, toBlock]


# First, we find a lowest block number with balance
# equal to that of toBlock
# Then we check if there were any outgoing txs between it and the last block,
# as it could've happened that several txs balanced themselves out
proc findBlockWithBalanceChange(address: types.Address, blockRange: BlockRange): int =
  var fromBlock = blockRange[0]
  var toBlock = blockRange[1]
  var blockNumber = toBlock
  let targetBalance = getValueForBlock(address, intToHex(toBlock), RemoteMethod.eth_getBalance)
  blockNumber = findLowestBlockNumber(address, [fromBlock, toBlock],
                         RemoteMethod.eth_getBalance, targetBalance)

  # Check if there were no txs in [blockNumber, toBlock]
  # Note that eth_getTransactionCount only counts outgoing transactions
  let txCount1 = getValueForBlock(address, intToHex(blockNumber), RemoteMethod.eth_getTransactionCount)
  let txCount2 = getValueForBlock(address, intToHex(toBlock), RemoteMethod.eth_getTransactionCount)
  if txCount1 == txCount2:
    # No txs occurred in between [blockNumber, toBlock]
    result = blockNumber
  else:
    # At least several txs occurred, so we find the number
    # of the lowest block containing txCount2
    blockNumber = findLowestBlockNumber(address, [fromBlock, toBlock],
                        RemoteMethod.eth_getTransactionCount, txCount2)
    let balance = getValueForBlock(address, intToHex(blockNumber), RemoteMethod.eth_getBalance)
    if balance == targetBalance:
      # This was the tx setting targetbalance
      result = blockNumber
    else:
      # This means there must have been an incoming tx inside [blockNumber, toBlock]
      result = findLowestBlockNumber(address, [blockNumber, toBlock],
                         RemoteMethod.eth_getBalance, targetBalance)


# We need to find exact block numbers containing balance changes
proc balanceBinarySearch*(address: types.Address, blockRange: BlockRange): BlockSeq =
  var blockNumbers: BlockSeq = @[]
  var fromBlock = blockRange[0]
  var toBlock = blockRange[1]
  while fromBlock < toBlock and len(blockNumbers) < txsPerPage:
    let blockNumber = findBlockWithBalanceChange(address, [fromBlock, toBlock])
    blockNumbers.add(blockNumber)

    toBlock = blockNumber - 1

  result = blockNumbers

proc filterTxsForAddress*(address: types.Address, blockNumbers: BlockSeq, txToData: var TransferMap) =
  for n in items(blockNumbers):
    let blockNumber = intToHex(n)
    let jsonNode = parseJSON(fmt"""["{blockNumber}", true]""")
    let resp = callRPC(web3Obj, RemoteMethod.eth_getBlockByNumber, jsonNode)

    let blockHash = resp["hash"].getStr
    let timestamp = fromHex[int](resp["timestamp"].getStr)
    for tx in items(resp["transactions"]):
      if cmpIgnoreCase(tx["from"].getStr, address) == 0 or
         cmpIgnoreCase(tx["to"].getStr, address) == 0:
        let txHash = tx["hash"].getStr
        let trView = Transfer(
          txType: TxType.eth,
          address: address,
          blockNumber: n,
          blockHash: blockHash,
          timestamp: timestamp,
          txHash: txHash)
        txToData[txHash] = trView


# Find blocks with balance changes and extract tx hashes from info
# fetched via eth_getBlockByNumber
proc fetchEthTxHashes(address: types.Address, txBlockRange: BlockRange, txToData: var TransferMap) =
  # Find block numbers containing balance changes
  var blockNumbers: BlockSeq = balanceBinarySearch(address, txBlockRange)

  # Get block info and extract txs pertaining to given address
  filterTxsForAddress(address, blockNumbers, txToData)

# Parse log entry in order to fetch fromAddr, toAddr, and value
proc parseLog(log: JsonNode): tuple[fromAddr: types.Address, toAddr: types.Address, value: int] =
  if len(log["topics"].getElems) < 3:
    echo "not enough topics for erc20 transfer", log["topics"]
    return

  let topic2 = log["topics"].getElems[1].getStr
  if len(topic2) != 66:
    echo "second topic is not padded to 32 byte address", topic2
    return

  let topic3 = log["topics"].getElems[2].getStr
  if len(topic3) != 66:
    echo "third topic is not padded to 32 byte address", topic3
    return

  let data = log["data"].getStr
  if len(data) != 66:
    echo "data is not padded to 32 byts big int", data
    return

  let value = fromHex[int](data)
  let fromAddr = "0x" & topic2[26..<66]
  let toAddr = "0x" & topic3[26..<66]

  return (fromAddr, toAddr, value)

# We have to invoke eth_getLogs twice for both
# incoming and outgoing ERC-20 transfers
proc fetchErc20Logs*(address: types.Address, blockRange: BlockRange, txToData: var TransferMap) {.gcsafe.} =
  let transferEventSignatureHash = "0x" & $keccak_256.digest("Transfer(address,address,uint256)")
  echo "transferEventSignatureHash :", transferEventSignatureHash

  let fromBlock = intToHex(blockRange[0])
  let toBlock = intToHex(blockRange[1])
  echo "fromBlock: ", fromBlock
  let addressPadded = "0x" & '0'.repeat(24) & address[2..<len(address)]
  echo "addressPadded: ", addressPadded
  var jsonNode = parseJson(fmt"""[{{
    "fromBlock": "{fromBlock}",
    "toBlock": "{toBlock}",
    "topics": ["{transferEventSignatureHash}", null, "{addressPadded}"]}}]""")

  var incomingLogs = callRPC(web3Obj, RemoteMethod.eth_getLogs, jsonNode)
  #echo "incomingLogs: ", incomingLogs
  jsonNode = parseJson(fmt"""[{{
    "fromBlock": "{fromBlock}",
    "toBlock": "{toBlock}",
    "topics": ["{transferEventSignatureHash}", "{addressPadded}", null]}}]""")

  var outgoingLogs = callRPC(web3Obj, RemoteMethod.eth_getLogs, jsonNode)
  #echo "outgoingLogs: ", outgoingLogs

  var logs: seq[JsonNode] = concat(incomingLogs.getElems, outgoingLogs.getElems)
  for obj in logs:
    let txHash = obj["transactionHash"].getStr
    let blockNumber = fromHex[int](obj["blockNumber"].getStr)
    let blockHash = obj["blockHash"].getStr
    let parsedLog = parseLog(obj)
    let trView = Transfer(
      txType: TxType.erc20,
      address: address,
      blockNumber: blockNumber,
      blockHash: blockHash,
      txHash: txHash,
      fromAddr: parsedLog.fromAddr,
      toAddr: parsedLog.toAddr,
      value: parsedLog.value,
      contract: obj["address"].getStr
      )
    txToData[txHash] = trView


proc fetchTxDetails*(address: types.Address, txToData: var TransferMap) =
  for tx in txToData.keys:
    let jsonNode = parseJSON(fmt"""["{tx}"]""")
    let txInfo = callRPC(web3Obj, RemoteMethod.eth_getTransactionByHash, jsonNode)
    let txReceipt = callRPC(web3Obj, RemoteMethod.eth_getTransactionReceipt, jsonNode)

    echo "fetchTxDetails txInfo: ", txInfo

    echo "fetchTxDetails txReceipt: ", txReceipt

    var trView = txToData[tx]
    trView.gasPrice = fromHex[int](txInfo["gasPrice"].getStr)
    trView.gasLimit = fromHex[int](txInfo["gas"].getStr)
    trView.gasUsed = fromHex[int](txReceipt["gasUsed"].getStr)
    trView.nonce = fromHex[int](txInfo["nonce"].getStr)
    trView.txStatus = fromHex[int](txReceipt["status"].getStr)
    trView.input = txInfo["input"].getStr
    if trView.txType == eth:
      trView.contract = txReceipt["contractAddress"].getStr
      trView.value = fromHex[int](txInfo["value"].getStr)
      trView.fromAddr = txInfo["from"].getStr
      trView.toAddr = txInfo["to"].getStr

    echo "gasLimit, ", fromHex[int](txInfo["gas"].getStr)
    echo "trView.gasLimit, ", trView.gasLimit
    txToData[tx] = trView


proc fetchDbData*(address: types.Address): TxDbData =
  var dbData = TxDbData()

  let query = fmt"""SELECT * FROM tx_history where address=?"""

  let infoQuery = fmt"""SELECT * FROM tx_history_info where address=?"""
  let dbResult = db.one(TransferInfo, infoQuery, address)
  if dbResult.isSome():
    dbData.info = dbResult.get()

  let transfer = db.one(query, address)
  echo "transfers: ", transfer.get().values()
  let transfers = db.all(Transfer, query, address)
  if len(transfers) > 0:
    for t in items(transfers):
      dbData.txToData.add(t.txHash, t)

  return dbData

proc saveTransferInfo*(transferInfo: TransferInfo) =
  let query = fmt"""
                 INSERT INTO tx_history_info(
                   {$TransferInfoCol.Address},
                   {$TransferInfoCol.Balance},
                   {$TransferInfoCol.BlockNumber},
                   {$TransferInfoCol.TxCount}
                 )
                 VALUES (?, ?, ?, ?)
                 """
  db.exec(query,
          transferInfo.address,
          transferInfo.balance,
          transferInfo.blockNumber,
          transferInfo.txCount)

proc saveTransfer*(transfer: Transfer) =
  let query = fmt"""
                 INSERT INTO tx_history(
                   {$TransferCol.Id},
                   {$TransferCol.TxType},
                   {$TransferCol.Address},
                   {$TransferCol.BlockNumber},
                   {$TransferCol.BlockHash},
                   {$TransferCol.Timestamp},
                   {$TransferCol.GasPrice},
                   {$TransferCol.GasLimit},
                   {$TransferCol.GasUsed},
                   {$TransferCol.Nonce},
                   {$TransferCol.TxStatus},
                   {$TransferCol.Input},
                   {$TransferCol.TxHash},
                   {$TransferCol.Value},
                   {$TransferCol.FromAddr},
                   {$TransferCol.ToAddr},
                   {$TransferCol.Contract},
                   {$TransferCol.NetworkID}
                 )
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 """
  db.exec(query,
          transfer.id,
          transfer.txType,
          transfer.address,
          transfer.blockNumber,
          transfer.blockHash,
          transfer.timestamp,
          transfer.gasPrice,
          transfer.gasLimit,
          transfer.gasUsed,
          transfer.nonce,
          transfer.txStatus,
          transfer.input,
          transfer.txHash,
          transfer.value,
          transfer.fromAddr,
          transfer.toAddr,
          transfer.contract,
          transfer.networkID)

proc writeToDb(dbData: TxDbData) =
  echo "writeToDb"
  saveTransferInfo(dbData.info)
  for transfer in dbData.txToData.values:
    saveTransfer(transfer)

# Used for passing address strings to scheduler thread
# bool parameter stands for addedOrRemoved flag
var chan: Channel[tuple[address: string, addOrRemove: bool]]

# Locks when tx data are being fetched in schedulerProc
var fetchLock: RLock


let schedulerInterval = 2 * 60 * 1000

# Main history fetching proc
proc schedulerProc() {.thread.} =
  while true:
    withRLock(fetchLock):
      var addresses = initHashSet[string]()

      # Fetch addresses from the channel
      while chan.peek() > 0:

        let t = chan.recv()
        let address = t[0]
        let addOrRemove: bool = t[1]
        if addOrRemove:
          addresses.incl(address)
        else:
          addresses.excl(address)


      # Update history for each address
      for address in items(addresses):
        var dbData = fetchDbData(address)

        let dbBlockNumber = dbData.info.blockNumber
        let dbTxCount = dbData.info.txCount
        let dbBalance = dbData.info.balance

        # If this is an initial wallet scan, all of [dbBlockNumber, dbTxCount, dbBalance]
        # will be zero
        var lastBlockNumber = getLastBlockNumber()
        if lastBlockNumber > dbBlockNumber:
          # There are new blocks, check if outgoing tx count or balance changed
          let txCount = getValueForBlock(address, intToHex(lastBlockNumber), RemoteMethod.eth_getTransactionCount)
          let balance = getValueForBlock(address, intToHex(lastBlockNumber), RemoteMethod.eth_getBalance)


          var txBlockRange: BlockRange
          if dbBlockNumber == 0:
            txBlockRange = txBinarySearch(address, lastBlockNumber)
          else:
            txBlockRange = [dbBlockNumber + 1, lastBlockNumber]
          var txToData = TransferMap()

          # Only fetch eth transfers if tx count or balance changed
          if dbTxCount != txCount or dbBalance != balance:
            fetchEthTxHashes(address, txBlockRange, txToData)

          # ERC-20 logs should be checked anyways
          fetchErc20Logs(address, txBlockRange, txToData)

          if len(txToData) > 0:
            fetchTxDetails(address, txToData)

          let transferInfo = TransferInfo(
            address: address,
            balance: balance,
            blockNumber: lastBlockNumber,
            txCount: txCount)
          writeToDb(TxDbData(info: transferInfo, txToData: txToData))

    sleep(schedulerInterval)

proc fetchTxHistory*(address: types.Address, toBlock: int): TransferMap =
  var txToData = TransferMap()

  # Find block range that we will search for balance changes
  let txBlockRange: BlockRange = txBinarySearch(address, toBlock)
  if txBlockRange == [0, 0]:
    # No txs found
    return txToData

  fetchEthTxHashes(address, txBlockRange, txToData)
  fetchErc20Logs(address, txBlockRange, txToData)

  fetchTxDetails(address, txToData)
  for transfer in txToData.values:
    saveTransfer(transfer)

  result = txToData

proc getTransfersByAddress*(address: types.Address, toBlock: int): TransferMap =
  var dbData = fetchDbData(address)
  if dbData.info.blockNumber == 0:
    # Nothing has been fetched yet, wait for
    # schedulerProc to fetch it
    withRLock(fetchLock):
      dbData = fetchDbData(address)
  elif dbData.info.blockNumber > toBlock:
    # Fetch a previous range
    let transferMap = fetchTxHistory(address, toBlock)
    dbData.txToData = transferMap

  return dbData.txToData

proc init*(addresses: seq[types.Address]) =

  initRLock(fetchLock)

  # Inititialize the channel and send account addresses
  chan.open()
  for a in addresses:
    chan.send((a, true))

  # Run the scheduler thread
  var schedulerThread: Thread[void]
  createThread(schedulerThread, schedulerProc)

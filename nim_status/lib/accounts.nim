import os, json
import sqlcipher, web3, chronos, json_serialization
import settings, database, conversions, callrpc

var db_conn*: DbConn
var web3_conn*: Web3

proc login*(accountData, password: string) =
  # TODO: get account, validate password, etc
  # TODO: should this be async?
  # TODO: db should have been initialized somewhere, not here
  # TODO: determine where will the DB connection live. In the meantime I'm storing it into a global variable
  # TODO: determine where the web3 conn will live

  let path =  getCurrentDir() / accountData & ".db"
  db_conn = initializeDB(path, password)

  # TODO: these settings should have been set when calling saveAccountAndLogin
  let settingsStr = """{
    "address": "0x1122334455667788990011223344556677889900",
    "chaos-mode": true,
    "networks/current-network": "mainnet_rpc",
    "dapps-address": "0x1122334455667788990011223344556677889900",
    "eip1581-address": "0x1122334455667788990011223344556677889900",
    "installation-id": "ABC-DEF-GHI",
    "key-uid": "XYZ",
    "latest-derived-path": 0,
    "networks/networks": [{"id":"mainnet_rpc","etherscan-link":"https://etherscan.io/address/","name":"Mainnet with upstream RPC","config":{"NetworkId":1,"DataDir":"/ethereum/mainnet_rpc","UpstreamConfig":{"Enabled":true,"URL":"wss://mainnet.infura.io/ws/v3/7230123556ec4a8aac8d89ccd0dd74d7"}}}],
    "name": "test",
    "photo-path": "ABXYZC",
    "preview-privacy?": false,
    "public-key": "0x123",
    "signing-phrase": "ABC DEF GHI",
    "wallet-root-address": "0x1122334455667788990011223344556677889900"
  }"""

  let settingsObj = JSON.decode(settingsStr, Settings, allowUnknownFields = true)
  let nodeConfig = %* {"config": 1}
  db_conn.createSettings(settingsObj, nodeConfig)

  web3_conn = newWeb3(getSettings(db_conn))


proc logout*() =
  waitFor web3_conn.close()
  db_conn.close()
  web3_conn = nil

proc test_removeDB*(accountData: string) = # TODO: remove this once proper db initialization is available
  let path =  getCurrentDir() / accountData & ".db"
  removeFile(path)
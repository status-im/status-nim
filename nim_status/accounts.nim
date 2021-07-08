import # nim libs
  json, options, strformat

import # vendor libs
  chronos, json_serialization, json_serialization/[reader, writer, lexer],
  sqlcipher

import # nim-status libs
  ./conversions, ./settings, ./database

# var db_conn*: DbConn
# var web3_conn*: Web3

# proc login*(accountData, password: string) =
#   # TODO: get account, validate password, etc
#   # TODO: should this be async?
#   # TODO: db should have been initialized somewhere, not here
#   # TODO: determine where will the DB connection live. In the meantime I'm storing it into a global variable
#   # TODO: determine where the web3 conn will live

#   let path =  getCurrentDir() / accountData & ".db"
#   db_conn = initializeDB(path, password)

#   # TODO: these settings should have been set when calling saveAccountAndLogin
#   let settingsStr = """{
#     "address": "0x1122334455667788990011223344556677889900",
#     "chaos-mode": true,
#     "networks/current-network": "mainnet_rpc",
#     "dapps-address": "0x1122334455667788990011223344556677889900",
#     "eip1581-address": "0x1122334455667788990011223344556677889900",
#     "installation-id": "ABC-DEF-GHI",
#     "key-uid": "XYZ",
#     "latest-derived-path": 0,
#     "networks/networks": [{"id":"mainnet_rpc","etherscan-link":"https://etherscan.io/address/","name":"Mainnet with upstream RPC","config":{"NetworkId":1,"DataDir":"/ethereum/mainnet_rpc","UpstreamConfig":{"Enabled":true,"URL":"wss://mainnet.infura.io/ws/v3/7230123556ec4a8aac8d89ccd0dd74d7"}}}],
#     "name": "test",
#     "photo-path": "ABXYZC",
#     "preview-privacy?": false,
#     "public-key": "0x123",
#     "signing-phrase": "ABC DEF GHI",
#     "wallet-root-address": "0x1122334455667788990011223344556677889900"
#   }"""

#   let settingsObj = JSON.decode(settingsStr, Settings, allowUnknownFields = true)
#   let nodeConfig = %* {"config": 1}
#   db_conn.createSettings(settingsObj, nodeConfig)

#   web3_conn = newWeb3(getSettings(db_conn))


# proc logout*() =
#   waitFor web3_conn.close()
#   db_conn.close()
#   web3_conn = nil

# proc test_removeDB*(accountData: string) = # TODO: remove this once proper db initialization is available
#   let path =  getCurrentDir() / accountData & ".db"
#   removeFile(path)

type
  PublicAccount* {.dbTableName("accounts").} = object
    creationTimestamp* {.serializedFieldName("creationTimestamp"), dbColumnName("creationTimestamp").}: int
    name* {.serializedFieldName("name"), dbColumnName("name").}: string
    identicon* {.serializedFieldName("identicon"), dbColumnName("identicon").}: string
    keycardPairing* {.serializedFieldName("keycardPairing"), dbColumnName("keycardPairing").}: string
    keyUid* {.serializedFieldName("keyUid"), dbColumnName("keyUid").}: string
    loginTimestamp* {.serializedFieldName("loginTimestamp"), dbColumnName("loginTimestamp").}: Option[int]

proc deleteAccount*(db: DbConn, keyUid: string) =
  var tblAccounts: PublicAccount
  let query = fmt"""DELETE FROM {tblAccounts.tableName}
                    WHERE       {tblAccounts.keyUid.columnName} = ?"""

  db.exec(query, keyUid)

proc getAccounts*(db: DbConn): seq[PublicAccount] =
  var tblAccounts: PublicAccount
  let query = fmt"""SELECT    {tblAccounts.creationTimestamp.columnName},
                              {tblAccounts.name.columnName},
                              {tblAccounts.loginTimestamp.columnName},
                              {tblAccounts.identicon.columnName},
                              {tblAccounts.keycardPairing.columnName},
                              {tblAccounts.keyUid.columnName}
                    FROM      {tblAccounts.tableName}
                    ORDER BY  {tblAccounts.creationTimestamp.columnName} ASC"""
  result = db.all(PublicAccount, query)

proc saveAccount*(db: DbConn, account: PublicAccount) =
  var tblAccounts: PublicAccount
  let query = fmt"""
    INSERT OR REPLACE INTO  {tblAccounts.tableName} (
                            {tblAccounts.creationTimestamp.columnName},
                            {tblAccounts.name.columnName},
                            {tblAccounts.identicon.columnName},
                            {tblAccounts.keycardPairing.columnName},
                            {tblAccounts.keyUid.columnName},
                            {tblAccounts.loginTimestamp.columnName})
    VALUES                  (?, ?, ?, ?, ?, NULL)"""

  db.exec(query, account.creationTimestamp, account.name, account.identicon, account.keycardPairing, account.keyUid)#, account.loginTimestamp)

proc toDisplayString*(account: PublicAccount): string =
  fmt"{account.name} ({account.keyUid})"

proc updateAccount*(db: DbConn, account: PublicAccount) =
  var tblAccounts: PublicAccount
  let query = fmt"""UPDATE  {tblAccounts.tableName}
                    SET     {tblAccounts.creationTimestamp.columnName} = ?,
                            {tblAccounts.name.columnName} = ?,
                            {tblAccounts.identicon.columnName} = ?,
                            {tblAccounts.keycardPairing.columnName} = ?,
                            {tblAccounts.loginTimestamp.columnName} = ?
                    WHERE   {tblAccounts.keyUid.columnName}= ?"""

  db.exec(query, account.creationTimestamp, account.name, account.identicon, account.keycardPairing, account.loginTimestamp, account.keyUid)

proc updateAccountTimestamp*(db: DbConn, loginTimestamp: int64, keyUid: string) =
  var tblAccounts: PublicAccount
  let query = fmt"""UPDATE  {tblAccounts.tableName}
                    SET     {tblAccounts.loginTimestamp.columnName} = ?
                    WHERE   {tblAccounts.keyUid.columnName} = ?"""

  db.exec(query, loginTimestamp, keyUid)

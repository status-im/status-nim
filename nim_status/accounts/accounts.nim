import # nim libs
  json, options, strformat, times

import # vendor libs
  chronos, json_serialization, json_serialization/[reader, writer, lexer],
  secp256k1, sqlcipher, web3/conversions as web3_conversions, web3/ethtypes

import # nim-status libs
  ../conversions, ../database, ../extkeys/types, ../settings

type
  Account* {.dbTableName("accounts").} = object
    address* {.serializedFieldName("address"), dbColumnName("address").}: Address
    wallet* {.serializedFieldName("wallet"), dbColumnName("wallet").}: Option[bool]
    chat* {.serializedFieldName("chat"), dbColumnName("chat").}: Option[bool]
    `type`* {.serializedFieldName("type"), dbColumnName("type").}: Option[string]
    storage* {.serializedFieldName("storage"), dbColumnName("storage").}: Option[string]
    path* {.serializedFieldName("path"), dbColumnName("path").}: Option[KeyPath]
    publicKey* {.serializedFieldName("pubkey"), dbColumnName("pubkey").}: Option[SkPublicKey]
    name* {.serializedFieldName("name"), dbColumnName("name").}: Option[string]
    color* {.serializedFieldName("color"), dbColumnName("color").}: Option[string]
    createdAt* {.serializedFieldName("created_at"), dbColumnName("created_at").}: DateTime
    updatedAt* {.serializedFieldName("updated_at"), dbColumnName("updated_at").}: DateTime

  AccountType* {.pure.} = enum
    Generated = "generated",
    Key       = "key",
    Seed      = "seed",
    Watch     = "watch"

proc createAccount*(db: DbConn, account: Account) =
  var tblAccounts: Account
  let query = fmt"""
    INSERT OR REPLACE INTO  {tblAccounts.tableName} (
                            {tblAccounts.address.columnName},
                            {tblAccounts.wallet.columnName},
                            {tblAccounts.chat.columnName},
                            {tblAccounts.`type`.columnName},
                            {tblAccounts.storage.columnName},
                            {tblAccounts.path.columnName},
                            {tblAccounts.publicKey.columnName},
                            {tblAccounts.name.columnName},
                            {tblAccounts.color.columnName},
                            {tblAccounts.createdAt.columnName},
                            {tblAccounts.updatedAt.columnName})
    VALUES                  (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

  let now = now()
  db.exec(query, account.address, account.wallet, account.chat,
    account.`type`, account.storage, account.path, account.publicKey,
    account.name, account.color, now, now)

proc deleteAccount*(db: DbConn, address: Address) =
  var tblAccounts: Account
  let query = fmt"""DELETE FROM {tblAccounts.tableName}
                    WHERE       {tblAccounts.address.columnName} = ?"""

  db.exec(query, address)

proc getAccounts*(db: DbConn): seq[Account] =
  var tblAccounts: Account
  let query = fmt"""SELECT    {tblAccounts.address.columnName},
                              {tblAccounts.wallet.columnName},
                              {tblAccounts.chat.columnName},
                              {tblAccounts.`type`.columnName},
                              {tblAccounts.storage.columnName},
                              {tblAccounts.path.columnName},
                              {tblAccounts.publicKey.columnName},
                              {tblAccounts.name.columnName},
                              {tblAccounts.color.columnName},
                              {tblAccounts.createdAt.columnName},
                              {tblAccounts.updatedAt.columnName}
                    FROM      {tblAccounts.tableName}
                    ORDER BY  {tblAccounts.createdAt.columnName} ASC"""
  result = db.all(Account, query)

proc updateAccount*(db: DbConn, account: Account) =
  var tblAccounts: Account
  let query = fmt"""UPDATE  {tblAccounts.tableName}
                    SET     {tblAccounts.wallet.columnName} = ?,
                            {tblAccounts.chat.columnName} = ?,
                            {tblAccounts.`type`.columnName} = ?,
                            {tblAccounts.storage.columnName} = ?,
                            {tblAccounts.path.columnName} = ?,
                            {tblAccounts.publicKey.columnName} = ?,
                            {tblAccounts.name.columnName} = ?,
                            {tblAccounts.color.columnName} = ?,
                            {tblAccounts.updatedAt.columnName} = ?
                    WHERE   {tblAccounts.address.columnName}= ?"""

  db.exec(query, account.wallet, account.chat, account.`type`, account.storage,
    account.path, account.publicKey, account.name, account.color, now(),
    account.address)

import # nim libs
  json, options, strformat

import # vendor libs
  chronos, json_serialization, json_serialization/[reader, writer, lexer],
  sqlcipher

import # nim-status libs
  ../conversions, ../settings, ../database

type
  PublicAccount* {.dbTableName("accounts").} = object
    creationTimestamp* {.serializedFieldName("creationTimestamp"), dbColumnName("creationTimestamp").}: int64
    name* {.serializedFieldName("name"), dbColumnName("name").}: string
    identicon* {.serializedFieldName("identicon"), dbColumnName("identicon").}: string
    keycardPairing* {.serializedFieldName("keycardPairing"), dbColumnName("keycardPairing").}: string
    keyUid* {.serializedFieldName("keyUid"), dbColumnName("keyUid").}: string
    loginTimestamp* {.serializedFieldName("loginTimestamp"), dbColumnName("loginTimestamp").}: Option[int64]

proc deleteAccount*(db: DbConn, keyUid: string) =
  var tblAccounts: PublicAccount
  let query = fmt"""DELETE FROM {tblAccounts.tableName}
                    WHERE       {tblAccounts.keyUid.columnName} = ?"""

  db.exec(query, keyUid)

proc getPublicAccount*(db: DbConn, keyUid: string): Option[PublicAccount] =
  var tblAccounts: PublicAccount
  let query = fmt"""SELECT    {tblAccounts.creationTimestamp.columnName},
                              {tblAccounts.name.columnName},
                              {tblAccounts.loginTimestamp.columnName},
                              {tblAccounts.identicon.columnName},
                              {tblAccounts.keycardPairing.columnName},
                              {tblAccounts.keyUid.columnName}
                    FROM      {tblAccounts.tableName}
                    WHERE     {tblAccounts.keyUid.columnName}= ?"""
  result = db.one(PublicAccount, query, keyUid)

proc getPublicAccounts*(db: DbConn): seq[PublicAccount] =
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

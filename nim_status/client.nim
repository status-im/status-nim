import # nim libs
  os, json

import # vendor libs
  confutils,
  json_serialization,
  sqlcipher

import # nim-status libs
  ./extkeys/types,
  ./accounts,
  ./chats,
  ./config,
  ./database,
  ./account/generator/generator,
  ./migrations/sql_scripts_accounts as acc_migration,
  ./migrations/sql_scripts_app as app_migration,
  ./multiaccount,
  ./settings

type StatusObject* = ref object
  accountsDB*: DbConn
  dataDir*: string
  userDB*: DbConn

proc new*(T: type StatusObject, dataDir: string,
  accountsDbFileName: string = "accounts.sql"): T =

  T(accountsDB: initializeDB(dataDir / accountsDbFileName),
    dataDir: dataDir)

proc getAccounts*(self: StatusObject): seq[PublicAccount] =
  getAccounts(self.accountsDB)

proc saveAccount*(self: StatusObject, account: PublicAccount) =
  saveAccount(self.accountsDB, account)

proc updateAccountTimestamp*(self: StatusObject, timestamp: int64, keyUid: string) =
  updateAccountTimestamp(self.accountsDB, timestamp, keyUid)

proc createSettings*(self: StatusObject, settings: Settings, nodeConfig: JsonNode) =
  createSettings(self.userDB, settings, nodeConfig)

proc getSettings*(self: StatusObject): Settings =
  getSettings(self.userDB)

proc login*(self: StatusObject, keyUid: string, password: string) =
  self.userDB = initializeDB(self.dataDir / keyUid & ".db", password)

proc logout*(self: StatusObject) =
  self.userDB.close()
  self.userDB = nil

proc multiAccountGenerateAndDeriveAccounts*(self: StatusObject,
  mnemonicPhraseLength: int, n: int, bip39Passphrase: string, paths: seq[KeyPath]
  ): seq[MultiAccount] =

  generateAndDeriveAccounts(mnemonicPhraseLength, n, bip39Passphrase, paths)

proc importMnemonicAndDeriveAccounts*(self: StatusObject,
  mnemonicPhrase: Mnemonic, bip39Passphrase: string, paths: seq[KeyPath]): MultiAccount =

  importMnemonicAndDeriveAccounts(mnemonicPhrase, bip39Passphrase, paths)

proc multiAccountStoreDerivedAccounts*(self: StatusObject,
  multiAcc: MultiAccount, password: string, dir: string) =

  storeDerivedAccounts(multiAcc, password, dir)

proc loadAccount*(self: StatusObject, address: string, password: string,
  dir: string = ""): Account =

  return loadAccount(address, password, dir)

proc closeUserDB*(self: StatusObject) =
  self.userDB.close()

proc loadChats*(self: StatusObject): seq[Chat] =
  getChats(self.userDB)

proc close*(self: StatusObject) =
  self.userDB.close()
  self.accountsDB.close()

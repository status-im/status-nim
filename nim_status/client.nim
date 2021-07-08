import # nim libs
  std/[os, json, times]

import # vendor libs
  confutils, eth/keyfile/uuid, sqlcipher

import # nim-status libs
  ./account/generator/generator, ./accounts, ./alias, ./chats, ./database,
  ./extkeys/types, ./identicon, ./settings

type StatusObject* = ref object
  accountsGenerator*: Generator
  accountsDb: DbConn
  dataDir*: string
  userDb: DbConn

proc new*(T: type StatusObject, dataDir: string,
  accountsDbFileName: string = "accounts.sql"): T =

  T(accountsDb: initializeDB(dataDir / accountsDbFileName),
    dataDir: dataDir, accountsGenerator: Generator.new())

proc getAccounts*(self: StatusObject): seq[PublicAccount] =
  self.accountsDb.getAccounts()

proc saveAccount*(self: StatusObject, account: PublicAccount) =
  self.accountsDb.saveAccount(account)

proc updateAccountTimestamp*(self: StatusObject, timestamp: int64, keyUid: string) =
  self.accountsDb.updateAccountTimestamp(timestamp, keyUid)

proc createSettings*(self: StatusObject, settings: Settings, nodeConfig: JsonNode) =
  self.userDb.createSettings(settings, nodeConfig)

proc getSettings*(self: StatusObject): Settings =
  self.userDb.getSettings()

proc login*(self: StatusObject, keyUid: string, password: string) =
  self.userDb = initializeDB(self.dataDir / keyUid & ".db", password)

proc logout*(self: StatusObject) =
  self.userDb.close()
  self.userDb = nil

proc createAccount*(self: StatusObject,
  mnemonicPhraseLength, n: int, bip39Passphrase, password: string,
  paths: seq[KeyPath], dir: string): PublicAccountResult =

  let
    gndAccounts = ?self.accountsGenerator.generateAndDeriveAddresses(
      mnemonicPhraseLength, n, bip39Passphrase, paths)
    gndAccount = gndAccounts[0]

  let
    accountInfos = ?self.accountsGenerator.storeDerivedAccounts(gndAccount.id,
      paths, password, dir)
    whisperAcct = accountInfos[2]
    account = PublicAccount(
      creationTimestamp: epochTime().int,
      name: whisperAcct.publicKey.generateAlias(),
      identicon: whisperAcct.publicKey.identicon(),
      keycardPairing: "",
      keyUid: gndAccount.keyUid # whisper key-uid
    )

  self.accountsDb.saveAccount(account)
  
  # create the user db on disk by initializing it then immediately closing it
  self.userDb = initializeDB(self.dataDir / account.keyUid & ".db", password)
  self.userDb.close()

  PublicAccountResult.ok(account)

proc importMnemonic*(self: StatusObject, mnemonic: Mnemonic,
  bip39Passphrase, password: string, paths: seq[KeyPath],
  dir: string): PublicAccountResult =

  let
    imported = ?self.accountsGenerator.importMnemonic(mnemonic, bip39Passphrase)
    accountInfos = ?self.accountsGenerator.storeDerivedAccounts(imported.id,
      paths, password, dir)
    whisperAcct = accountInfos[2]
    account = PublicAccount(
      creationTimestamp: epochTime().int,
      name: whisperAcct.publicKey.generateAlias(),
      identicon: whisperAcct.publicKey.identicon(),
      keycardPairing: "",
      keyUid: imported.keyUid # whisper key-uid
    )

  self.accountsDb.saveAccount(account)

  # create the user db by initializing it then immediately closing it
  self.userDb = initializeDB(self.dataDir / account.keyUid & ".db", password)
  self.userDb.close()

  PublicAccountResult.ok(account)

proc loadAccount*(self: StatusObject, address: string, password: string,
  dir: string = ""): LoadAccountResult =

  self.accountsGenerator.loadAccount(address, password, dir)

proc closeUserDB*(self: StatusObject) =
  self.userDb.close()

proc loadChats*(self: StatusObject): seq[Chat] =
  getChats(self.userDb)

proc close*(self: StatusObject) =
  self.userDb.close()
  self.accountsDb.close()

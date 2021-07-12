import # nim libs
  std/[os, json, times]

import # vendor libs
  confutils, eth/keyfile/uuid, secp256k1, sqlcipher

import # nim-status libs
  ./accounts/[accounts, public_accounts],
  ./accounts/generator/generator,
  ./accounts/generator/account as generator_account, ./alias, ./chats,
  ./conversions, ./database, ./extkeys/types, ./identicon, ./settings

type
  StatusObject* = ref object
    accountsGenerator*: Generator
    accountsDb: DbConn
    dataDir*: string
    userDb: DbConn

proc new*(T: type StatusObject, dataDir: string,
  accountsDbFileName: string = "accounts.sql"): T =

  T(accountsDb: initializeDB(dataDir / accountsDbFileName),
    dataDir: dataDir, accountsGenerator: Generator.new())

proc getPublicAccounts*(self: StatusObject): seq[PublicAccount] =
  self.accountsDb.getPublicAccounts()

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

proc storeDerivedAccountsInDb(self: StatusObject, id: UUID, keyUid: string,
  paths: seq[KeyPath], password, dir: string): PublicAccountResult =

  let
    accountInfos = ?self.accountsGenerator.storeDerivedAccounts(id, paths,
      password, dir)
    whisperAcct = accountInfos[2]
    pubAccount = PublicAccount(
      creationTimestamp: epochTime().int,
      name: whisperAcct.publicKey.generateAlias(),
      identicon: whisperAcct.publicKey.identicon(),
      keycardPairing: "",
      keyUid: keyUid # whisper key-uid
    )

  self.accountsDb.saveAccount(pubAccount)
  
  let
    defaultWalletAccountDerived = accountInfos[3]
    defaultWalletPubKeyResult = SkPublicKey.fromHex(defaultWalletAccountDerived.publicKey)
    whisperAccountPubKeyResult = SkPublicKey.fromHex(whisperAcct.publicKey)
  
  if defaultWalletPubKeyResult.isErr:
    return PublicAccountResult.err $defaultWalletPubKeyResult.error
  if whisperAccountPubKeyResult.isErr:
    return PublicAccountResult.err $whisperAccountPubKeyResult.error

  let
    defaultWalletAccount = accounts.Account(
      address: defaultWalletAccountDerived.address.parseAddress,
      wallet: true.some,
      chat: false.some,
      `type`: some($AccountType.Seed),
      storage: string.none,
      path: paths[3].some,
      publicKey: defaultWalletPubKeyResult.get.some,
      name: "Status account".some,
      color: "#4360df".some
    )
    whisperAccount = accounts.Account(
      address: whisperAcct.address.parseAddress,
      wallet: false.some,
      chat: true.some,
      `type`: some($AccountType.Seed),
      storage: string.none,
      path: paths[2].some,
      publicKey: whisperAccountPubKeyResult.get.some,
      name: pubAccount.name.some,
      color: "#4360df".some
    )
  self.userDb.createAccount(defaultWalletAccount)
  self.userDb.createAccount(whisperAccount)

  PublicAccountResult.ok(pubAccount)

proc createAccount*(self: StatusObject,
  mnemonicPhraseLength, n: int, bip39Passphrase, password: string,
  paths: seq[KeyPath], dir: string): PublicAccountResult =

  let
    gndAccounts = ?self.accountsGenerator.generateAndDeriveAddresses(
      mnemonicPhraseLength, n, bip39Passphrase, paths)
    gndAccount = gndAccounts[0]

  # create the user db on disk by initializing it then immediately closing it
  self.userDb = initializeDB(self.dataDir / gndAccount.keyUid & ".db", password)
  let pubAccount = ?self.storeDerivedAccountsInDb(gndAccount.id, gndAccount.keyUid, paths,
    password, dir)
  self.userDb.close()

  PublicAccountResult.ok(pubAccount)

proc importMnemonic*(self: StatusObject, mnemonic: Mnemonic,
  bip39Passphrase, password: string, paths: seq[KeyPath],
  dir: string): PublicAccountResult =

  let imported = ?self.accountsGenerator.importMnemonic(mnemonic, bip39Passphrase)

  # create the user db by initializing it then closing it
  self.userDb = initializeDB(self.dataDir / imported.keyUid & ".db", password)
  let pubAccount = ?self.storeDerivedAccountsInDb(imported.id, imported.keyUid, paths, password,
    dir)
  self.userDb.close()

  PublicAccountResult.ok(pubAccount)

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

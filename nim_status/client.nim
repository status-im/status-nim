import # nim libs
  std/[os, json, strformat, times, typetraits]

import # vendor libs
  confutils, eth/keyfile/uuid, secp256k1, sqlcipher, stew/results

import # nim-status libs
  ./accounts/[accounts, public_accounts],
  ./accounts/generator/generator,
  ./accounts/generator/account as generator_account, ./alias, ./chats,
  ./conversions, ./database, ./extkeys/[paths, types], ./identicon, ./settings,
  ./settings/types as settings_types, ./util

export results

type
  CreateSettingsResult* = Result[void, string]
  # GetSettingResult*[T] = Result[T, string]
  GetSettingsResult* = Result[Settings, string]
  LoginResult* = Result[PublicAccount, string]
  LogoutResult* = Result[void, string]
  StatusObject* = ref object
    accountsGenerator*: Generator
    accountsDb: DbConn
    dataDir*: string
    userDbConn: DbConn 
      # Do not use self.userDbConn directly in exported procs. Use self.userDb,
      # self.initUserDb, self.closeUserDb, and self.isLoggedIn instead.

proc new*(T: type StatusObject, dataDir: string,
  accountsDbFileName: string = "accounts.sql"): T =

  T(accountsDb: initializeDB(dataDir / accountsDbFileName),
    dataDir: dataDir, accountsGenerator: Generator.new())

proc userDb(self: StatusObject): DbConn =
  if distinctBase(self.userDbConn).isNil:
    raise newException(IOError,
      "User DB not initialized. Please login first.")
  self.userDbConn

proc closeUserDb(self: StatusObject) =
  self.userDb.close()
  self.userDbConn = nil

proc isLoggedIn*(self: StatusObject): bool =
  not distinctBase(self.userDbConn).isNil

proc close*(self: StatusObject) =
  if self.isLoggedIn:
    self.closeUserDb()
  self.accountsDb.close()

proc initUserDb(self: StatusObject, keyUid, password: string) =
  self.userDbConn = initializeDB(self.dataDir / keyUid & ".db", password)

proc storeDerivedAccount(self: StatusObject, id: UUID, keyUid: string,
  path: KeyPath, name, password, dir: string,
  accountType: AccountType): PublicAccountResult =

  let
    accountInfos = ?self.accountsGenerator.storeDerivedAccounts(id, @[path],
      password, dir)
    acct = accountInfos[0]
    pubAccount = PublicAccount(
      creationTimestamp: getTime().toUnix,
      name: acct.publicKey.generateAlias(),
      identicon: acct.publicKey.identicon(),
      keycardPairing: "",
      keyUid: keyUid # whisper key-uid
    )

  let walletPubKeyResult = SkPublicKey.fromHex(acct.publicKey)
  
  if walletPubKeyResult.isErr:
    return PublicAccountResult.err $walletPubKeyResult.error

  var walletName = name
  if walletName == "":
    let pathStr = $path
    walletName = fmt"Wallet account {pathStr[pathStr.len - 1]}"

  let
    walletAccount = accounts.Account(
      address: acct.address.parseAddress,
      wallet: true.some,
      chat: false.some,
      `type`: some($accountType),
      storage: string.none,
      path: path.some,
      publicKey: walletPubKeyResult.get.some,
      name: walletName.some,
      color: "#4360df".some
    )
  self.userDb.createAccount(walletAccount)

  PublicAccountResult.ok(pubAccount)

proc storeDerivedAccounts(self: StatusObject, id: UUID, keyUid: string,
  paths: seq[KeyPath], password, dir: string): PublicAccountResult =
  let
    defaultWalletAcctIdx = paths.indexOf(PATH_DEFAULT_WALLET)
    whisperAcctIdx = paths.indexOf(PATH_WHISPER)

  if defaultWalletAcctIdx == -1:
    return PublicAccountResult.err "Default wallet account path not provided"
  if whisperAcctIdx == -1:
    return PublicAccountResult.err "Whisper account path not provided"

  let
    accountInfos = ?self.accountsGenerator.storeDerivedAccounts(id, paths,
      password, dir)
    whisperAcct = accountInfos[whisperAcctIdx]
    pubAccount = PublicAccount(
      creationTimestamp: getTime().toUnix,
      name: whisperAcct.publicKey.generateAlias(),
      identicon: whisperAcct.publicKey.identicon(),
      keycardPairing: "",
      keyUid: keyUid # whisper key-uid
    )

  self.accountsDb.saveAccount(pubAccount)
  
  let
    defaultWalletAccountDerived = accountInfos[defaultWalletAcctIdx]
    defaultWalletPubKeyResult =
      SkPublicKey.fromHex(defaultWalletAccountDerived.publicKey)
    whisperAccountPubKeyResult =
      SkPublicKey.fromHex(whisperAcct.publicKey)
  
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
      path: paths[defaultWalletAcctIdx].some,
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
      path: paths[whisperAcctIdx].some,
      publicKey: whisperAccountPubKeyResult.get.some,
      name: pubAccount.name.some,
      color: "#4360df".some
    )
  self.userDb.createAccount(defaultWalletAccount)
  self.userDb.createAccount(whisperAccount)

  PublicAccountResult.ok(pubAccount)

proc addWalletAccount*(self: StatusObject, name, password,
  #[privateKey: Option[string],]# dir: string): PublicAccountResult =

  if not self.isLoggedIn:
    return PublicAccountResult.err "Not logged in. You must be logged in to " &
      "create a new wallet account."

  let
    address = self.userDb.getSetting(string, SettingsCol.WalletRootAddress,
      $PATH_WALLET_ROOT)
    lastDerivedPathIdx =
      self.userDb.getSetting(int, SettingsCol.LatestDerivedPath, 0)
    loadedAccount = ?self.accountsGenerator.loadAccount(address, password, dir)
    newIdx = lastDerivedPathIdx + 1
    path = fmt"{PATH_WALLET_ROOT}/{newIdx}"
    pubAccount = ?self.storeDerivedAccount(loadedAccount.id,
      loadedAccount.keyUid, KeyPath path, name, password, dir,
      AccountType.Generated)

  self.userDb.saveSetting(SettingsCol.LatestDerivedPath, newIdx)

  PublicAccountResult.ok(pubAccount)

proc createAccount*(self: StatusObject,
  mnemonicPhraseLength, n: int, bip39Passphrase, password: string,
  paths: seq[KeyPath], dir: string): PublicAccountResult =

  if self.isLoggedIn:
    return PublicAccountResult.err "Already logged in. Must be logged out to " &
      "create a new account."

  let
    gndAccounts = ?self.accountsGenerator.generateAndDeriveAddresses(
      mnemonicPhraseLength, n, bip39Passphrase, paths)
    gndAccount = gndAccounts[0]

  self.initUserDb(gndAccount.keyUid, password)
  let pubAccount = ?self.storeDerivedAccounts(gndAccount.id, gndAccount.keyUid,
    paths, password, dir)

  # TODO: create full settings. For now, we will just store a single value
  # so we can retrieve it later
  # self.userDb.createSettings(settings: Settings, nodeConfig: JsonNode)

  self.userDb.saveSetting(SettingsCol.LatestDerivedPath, 0)
  self.closeUserDb()

  PublicAccountResult.ok(pubAccount)

# TODO: Remove this from the client if not needed. This is only used for tests
# right now.
proc createSettings*(self: StatusObject, settings: Settings,
  nodeConfig: JsonNode): CreateSettingsResult =

  if not self.isLoggedIn:
    return CreateSettingsResult.err "Not logged in. You must be logged in to " &
      "create settings."
  try:
    self.userDb.createSettings(settings, nodeConfig)
    return CreateSettingsResult.ok
  except Exception as e:
    return CreateSettingsResult.err e.msg

proc getPublicAccounts*(self: StatusObject): seq[PublicAccount] =
  self.accountsDb.getPublicAccounts()

# proc getSetting*[T](self: StatusObject, U: typedesc[T],
#   setting: SettingsCol): GetSettingResult[T] =

#   if not self.isLoggedIn:
#     return GetSettingResult.err "Not logged in. Must be logged in to get " &
#       "settings."
#   try:
#     let opt = self.userDb.getSetting(U, setting)
#     if opt.isNone:
#       return GetSettingResult.err "asdf"
#     return GetSettingResult.ok opt.get
#   except Exception as e:
#     return GetSettingResult.err e.msg

# proc getSetting*[T](self: StatusObject, U: typedesc[T], setting: SettingsCol,
#   defaultValue: T): GetSettingResult[T] =

#   if not self.isLoggedIn:
#     return GetSettingResult.err "Not logged in. Must be logged in to get " &
#       "settings."
#   try:
#     let opt = self.userDb.getSetting(U, setting)
#     if opt.isNone:
#       return GetSettingResult.err "asdf"
#     return GetSettingResult.ok opt.get
#   except Exception as e:
#     return GetSettingResult.err e.msg

proc getSettings*(self: StatusObject): GetSettingsResult =
  if not self.isLoggedIn:
    return GetSettingsResult.err "Not logged in. Must be logged in to get " &
      "settings."
  try:
    return GetSettingsResult.ok self.userDb.getSettings()
  except Exception as e:
    return GetSettingsResult.err e.msg

proc importMnemonic*(self: StatusObject, mnemonic: Mnemonic,
  bip39Passphrase, password: string, paths: seq[KeyPath],
  dir: string): PublicAccountResult =

  if self.isLoggedIn:
    return PublicAccountResult.err "Already logged in. Must be logged out to " &
      "import an account."

  let imported = ?self.accountsGenerator.importMnemonic(mnemonic,
    bip39Passphrase)

  try:
    self.initUserDb(imported.keyUid, password)
    let pubAccount = ?self.storeDerivedAccounts(imported.id, imported.keyUid,
      paths, password, dir)
    self.closeUserDb()
    PublicAccountResult.ok(pubAccount)
  except Exception as e:
    return PublicAccountResult.err e.msg

proc loadChats*(self: StatusObject): seq[Chat] =
  getChats(self.userDb)

proc login*(self: StatusObject, keyUid, password: string): LoginResult =
  let account = self.accountsDb.getPublicAccount(keyUid)
  if account.isNone:
    return LoginResult.err "Could not find account with keyUid " & keyUid
  try:
    self.initUserDb(keyUid, password)
    LoginResult.ok account.get
  except Exception as e:
    return LoginResult.err e.msg

proc logout*(self: StatusObject): LogoutResult =
  try:
    self.closeUserDb()
    LogoutResult.ok
  except Exception as e:
    return LogoutResult.err e.msg

proc saveAccount*(self: StatusObject, account: PublicAccount) =
  self.accountsDb.saveAccount(account)

proc updateAccountTimestamp*(self: StatusObject, timestamp: int64,
  keyUid: string) =

  self.accountsDb.updateAccountTimestamp(timestamp, keyUid)


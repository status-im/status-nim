import # nim libs
  json, options, os, times, unittest

import # vendor libs
  chronos, json_serialization, secp256k1, sqlcipher, web3/ethtypes

import # nim-status libs
  ../../nim_status/[database, conversions],
  ../../nim_status/accounts/accounts, ../../nim_status/extkeys/types,
  ../test_helpers

procSuite "accounts":

  var account = Account(
    address: "0xdeadbeefdeadbeefdeadbeefdeadbeef11111111".parseAddress,
    wallet: true.some,
    chat: false.some,
    `type`: "type".some,
    storage: "storage".some,
    path: KeyPath("m/43'/60'/1581'/0'/0").some,
    publicKey: some(SkPublicKey.fromHex("0x04986dee3b8afe24cb8ccb2ac23dac3f8c43d22850d14b809b26d6b8aa5a1f47784152cd2c7d9edd0ab20392a837464b5a750b2a7f3f06e6a5756b5211b6a6ed05").get),
    name: "name".some,
    color: "#4360df".some
  )

  asyncTest "createAccount":
    let
      password = "qwerty"
      path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)

    let db = initializeDB(path, password)

    db.createAccount(account)

    # check that the values saved correctly
    let
      accountList = db.getAccounts()
      accountFromDb = accountList[0]

    check:
      accountList.len == 1
      accountFromDb.address == account.address
      accountFromDb.wallet.get == account.wallet.get
      accountFromDb.chat.get == account.chat.get
      accountFromDb.`type`.get == account.`type`.get
      accountFromDb.storage.get == account.storage.get
      accountFromDb.path.get.string == account.path.get.string
      accountFromDb.publicKey.get == account.publicKey.get
      accountFromDb.name.get == account.name.get
      accountFromDb.color.get == account.color.get
      accountFromDb.createdAt == accountFromDb.updatedAt

    db.close()
    removeFile(path)

  asyncTest "updateAccount":
    let
      password = "qwerty"
      path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)

    let db = initializeDB(path, password)

    db.createAccount(account)

    # check that the values saved correctly
    var
      accountList = db.getAccounts()
      accountFromDb = accountList[0]

    # change values, then update
    let
      address_updated = "0xdeadbeefdeadbeefdeadbeefdeadbeef11111111".parseAddress
      wallet_updated = false.some
      chat_updated = true.some
      type_updated = "type_changed".some
      storage_updated = "storage_changed".some
      path_updated = KeyPath("m/44'/0'/0'/0/0").some
      publicKey_updated = some(SkPublicKey.fromHex("0x03ddb90a4f67a81adf534bc19ed06d1546a3cad16a3b2995e18e3d7af823fe5c9a").get)
      name_updated = "name_updated".some
      color_updated = "#1360df".some
    
    accountFromDb.address = address_updated
    accountFromDb.wallet = wallet_updated
    accountFromDb.chat = chat_updated
    accountFromDb.`type` = type_updated
    accountFromDb.storage = storage_updated
    accountFromDb.path = path_updated
    accountFromDb.publicKey = publicKey_updated
    accountFromDb.name = name_updated
    accountFromDb.color = color_updated

    db.updateAccount(accountFromDb)

    accountList = db.getAccounts()
    accountFromDb = accountList[0]

    check:
      accountList.len == 1
      accountFromDb.address == address_updated
      accountFromDb.wallet.get == wallet_updated.get
      accountFromDb.chat.get == chat_updated.get
      accountFromDb.`type`.get == type_updated.get
      accountFromDb.storage.get == storage_updated.get
      accountFromDb.path.get.string == path_updated.get.string
      accountFromDb.publicKey.get == publicKey_updated.get
      accountFromDb.name.get == name_updated.get
      accountFromDb.color.get == color_updated.get
      accountFromDb.createdAt != accountFromDb.updatedAt

    db.close()
    removeFile(path)
  
  asyncTest "deleteAccount":
    let
      password = "qwerty"
      path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)

    let db = initializeDB(path, password)

    db.createAccount(account)

    # check that the values saved correctly
    var
      accountList = db.getAccounts()
      accountFromDb = accountList[0]

    check:
      accountList.len == 1

    db.deleteAccount(accountFromDb.address)

    accountList = db.getAccounts()

    check:
      accountList.len == 0

    db.close()
    removeFile(path)

import # nim libs
  json, options, os, times, unittest

import # vendor libs
  chronos, json_serialization, sqlcipher, web3/conversions as web3_conversions

import # nim-status libs
  ../nim_status/[accounts, database, conversions],
  ./test_helpers

procSuite "accounts":
  asyncTest "saveAccount, updateAccountTimestamp, deleteAccount":
    let path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)
    let db = initializeDB(path)

    let timestamp1 = epochTime().int

    var account:PublicAccount = PublicAccount(
      creationTimestamp: timestamp1,
      name: "Test",
      identicon: "data:image/png;base64,something",
      keycardPairing: "",
      keyUid: "0x1234"
    )

    db.saveAccount(account)

    # check that the values saved correctly
    var accountList = db.getAccounts()
    check:
      accountList[0].creationTimestamp == timestamp1
      accountList[0].name == account.name
      accountList[0].identicon == account.identicon
      accountList[0].keycardPairing == account.keycardPairing
      accountList[0].keyUid == account.keyUid
      accountList[0].loginTimestamp.isSome == false

    let timestamp2 = timestamp1 + 100

    # check that we can update name, identicon, keycardPairing, loginTimestamp
    account.name = account.name & "_updated"
    account.identicon = account.identicon & "_updated"
    account.keycardPairing = account.keycardPairing & "_updated"
    account.loginTimestamp = timestamp2.some
    db.updateAccount(account)
    accountList = db.getAccounts()

    check:
      accountList.len == 1
      accountList[0].creationTimestamp == timestamp1
      accountList[0].name == account.name
      accountList[0].identicon == account.identicon
      accountList[0].keycardPairing == account.keycardPairing
      accountList[0].loginTimestamp == account.loginTimestamp
      accountList[0].keyUid == account.keyUid # should not have been updated

    # check that we only update timestamp with `updateAccountTimestamp`
    let newTimestamp = 1
    db.updateAccountTimestamp(newTimestamp, account.keyUid)
    accountList = db.getAccounts()

    check:
      accountList.len == 1
      accountList[0].name == account.name
      accountList[0].identicon == account.identicon
      accountList[0].keycardPairing == account.keycardPairing
      accountList[0].loginTimestamp.isSome and
        accountList[0].loginTimestamp.get == newTimestamp
      accountList[0].keyUid == account.keyUid

    # check that we can delete accounts
    db.deleteAccount(account.keyUid)
    accountList = db.getAccounts()

    check:
      accountList.len == 0

    db.close()
    removeFile(path)

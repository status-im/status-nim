import # nim libs
  std/[strformat, strutils, tables, unittest]

import # vednor libs
  chronos, eth/keys, eth/keyfile/uuid

import # nim-status libs
  ../../../nim_status/accounts/generator/generator,
  ../../../nim_status/extkeys/types, ../../test_helpers


procSuite "generator":

  type
    TestAccount = ref object
      bip39Passphrase: string
      bip44Address0: string
      bip44Address1: string
      bip44Key0: string
      bip44PubKey0: string
      encryptionPassword: string
      extendedMasterKey: string
      extendedSecretKey: string
      mnemonic: string
  
  let testAccount = TestAccount(
    bip39Passphrase:    "TREZOR",
    bip44Key0:          "0x62f1d86b246c81bdd8f6c166d56896a4a5e1eddbcaebe06480e5c0bc74c28224",
    bip44PubKey0:       "0x04986dee3b8afe24cb8ccb2ac23dac3f8c43d22850d14b809b26d6b8aa5a1f47784152cd2c7d9edd0ab20392a837464b5a750b2a7f3f06e6a5756b5211b6a6ed05",
    bip44Address0:      "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6",
    bip44Address1:      "0x7AF7283bd1462C3b957e8FAc28Dc19cBbF2FAdfe",
    encryptionPassword: "TEST_PASSWORD",
    extendedMasterKey:  "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF",
    extendedSecretKey:  "cbedc75b0d6412c85c79bc13875112ef912fd1e756631b5a00330866f22ff184",
    mnemonic:           "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
  )

  test "generate":
    let gntr = Generator.new()
    assert gntr.accounts.len == 0, "should start with 0 accounts"

    let generateResult = gntr.generate(12, 5, "")

    assert generateResult.isOk, "error generating accounts: " &
      generateResult.error
    
    echo "Generated Accounts [uuid: pubkey]"
    for uuid, acct in gntr.accounts.pairs:
      echo $uuid & ": " & $ acct.secretKey.toPublicKey

    assert gntr.accounts.len == 5, "should have created 5 accounts, but " &
      "created " & $gntr.accounts.len

    for genAcctInfo in generateResult.get:
      let words = genAcctInfo.mnemonic.string.split(" ")
      assert words.len == 12, "mnemonic should contain 12 words"

  test "import mnemonic":
    let gntr = Generator.new()
    assert gntr.accounts.len == 0, "should start with 0 accounts"

    let importedResult = gntr.importMnemonic(Mnemonic testAccount.mnemonic,
      testAccount.bip39Passphrase)

    echo "Generated Accounts [uuid: secret key]"
    for uuid, acct in gntr.accounts.pairs:
      echo $uuid & ": " & $ acct.secretKey

    assert importedResult.isOk, "failed to import mnemonic"
    assert gntr.accounts.len == 1, "should have created 1 account"

    let
      imported = importedResult.get
      generatorAcct = gntr.accounts[$imported.id]

    assert testAccount.extendedSecretKey ==
      $ generatorAcct.secretKey, "extended key's secret key should match"
    assert testAccount.extendedSecretKey ==
      $ generatorAcct.extendedKey.secretKey, "extended key's secret key " &
        "should match"

  test "derive addresses":
    let gntr = Generator.new()
    assert gntr.accounts.len == 0, "should start with 0 accounts"

    let importedResult = gntr.importMnemonic(Mnemonic testAccount.mnemonic,
      testAccount.bip39Passphrase)

    echo "Generated Accounts [uuid: secret key]"
    for uuid, acct in gntr.accounts.pairs:
      echo $uuid & ": " & $ acct.secretKey
    echo "" # blank line

    assert importedResult.isOk, "failed to import mnemonic"
    assert gntr.accounts.len == 1, "should have created 1 account"

    let
      path0 = KeyPath "m/44'/60'/0'/0/0"
      path1 = KeyPath "m/44'/60'/0'/0/1"
      paths = @[path0, path1]
      imported = importedResult.get
      derivedResult = gntr.deriveAddresses(imported.id, paths)

    assert derivedResult.isOk, "failed to derive addresses: " &
      derivedResult.error

    let derived = derivedResult.get
    
    echo "Imported Accounts [path: address]"
    var i = 0
    for accountInfo in derived:
      echo fmt"{paths[i].string}: {accountInfo.address}"
      i = i + 1

    assert derived.len == 2, "should have derived 2 addresses"
    assert testAccount.bip44Address0 == derived[0].address,
      "first derived address should match bip44Address0"
    assert testAccount.bip44Address1 == derived[1].address,
      "second derived address should match bip44Address1"

  test "import private key":
    let gntr = Generator.new()
    assert gntr.accounts.len == 0, "should start with 0 accounts"

    let idAcctInfoResult = gntr.importPrivateKey(testAccount.bip44Key0)

    echo "Generated Accounts [uuid: secret key]"
    for uuid, acct in gntr.accounts.pairs:
      echo $uuid & ": " & $ acct.secretKey

    assert idAcctInfoResult.isOk, "failed to import private key: " &
      idAcctInfoResult.error
    assert gntr.accounts.len == 1, "generator should have imported 1 account"

    let idAcctInfo = idAcctInfoResult.get
    assert testAccount.bip44PubKey0 == idAcctInfo.publicKey, "public keys " &
      "should match"
    assert testAccount.bip44Address0 == idAcctInfo.address, "addresses " &
      "should match"

  # TODO: this needs to be done so that we can ensure created master/child
  # keys are hardened
  # test "derive address from imported key":
  #   let gntr = Generator.new()
  #   assert gntr.accounts.len == 0, "should start with 0 accounts"

  #   var rng = keys.newRng()[]
  #   let
  #     randomKey = SkSecretKey(PrivateKey.random(rng))
  #     hex = randomKey.toHex
  #     importedResult = gntr.importPrivateKey(hex)

  #   echo "Generated Accounts [uuid: secret key]"
  #   for uuid, acct in gntr.accounts.pairs:
  #     echo $uuid & ": " & $ acct.secretKey

  #   assert importedResult.isOk, "failed to import private key: " &
  #     importedResult.error
  #   assert gntr.accounts.len == 1, "generator should have imported 1 account"

  #   # normal imported accounts cannot derive child accounts,
  #   # but only the address/pubblic key of the current key.
  #   let
  #     imported = importedResult.get
  #     paths = @[KeyPath "m/44'/60'/0'/0", KeyPath "m/44'/60'/0'/1"]

  #   for path in paths:
  #     let derivedResult = gntr.deriveAddresses(imported.id, @[path])

  #     assert derivedResult.isOk, "failed to derive address: " &
  #       derivedResult.error

  #     let
  #       derived = derivedResult.get
  #       expectedAddress = PublicKey(randomKey.toPublicKey).toChecksumAddress
      
  #     assert expectedAddress == derived[0].address, "addresses should match, " &
  #       fmt"expectedAddress: {expectedAddress}, actualAddress: {derived[0].address}"

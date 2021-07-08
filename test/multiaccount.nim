import # nim libs
  os, unittest

import # vednor libs
  chronos, eth/[keys, p2p], stew/byteutils

import # nim-status libs
  ../nim_status/account/generator/generator, ../nim_status/extkeys/paths,
  ../nim_status/multiaccount, ./test_helpers


procSuite "multiaccount":
  test "multiaccount":
    let entropyStrength = mnemonicPhraseLengthToEntropyStrength(12)
    assert entropyStrength.int == 128

    let passphrase = ""
    let multiAccounts = generateAndDeriveAccounts(12, 1, passphrase,
      @[PATH_WALLET_ROOT, PATH_DEFAULT_WALLET, PATH_WHISPER])

    #assert len(multiAccounts) == 5

    let multiAcc = multiAccounts[0]
    assert len(multiAcc.accounts) == 3

    let password = "qwerty"
    let dir = "test_accounts"
    echo "MultiAcc mnemonic: ", multiAcc.mnemonic.string

    let importedMultiAcc = importMnemonic(multiAcc.mnemonic, passphrase)

    assert string.fromBytes(openArray[byte](importedMultiAcc.keyseed)) ==
      string.fromBytes(openArray[byte](multiAcc.keyseed))

    echo "MultiAcc keyseed: ", string.fromBytes(openArray[byte](
      multiAcc.keyseed))

    createDir(dir)

    storeDerivedAccounts(multiAccounts[0], password, dir, workfactor = 100)

    let chatAddress = multiAcc.accounts[2].address

    let chatAccount = loadAccount(chatAddress, password, dir)

    echo "chatAccount:"
    echo chatAccount

    assert chatAccount.address == chatAddress

    removeDir(dir)

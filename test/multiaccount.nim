import # nim libs
  os, unittest

import # vednor libs
  chronos, eth/[keys, p2p], stew/byteutils

import # nim-status libs
  ../nim_status/account/generator/generator, ../nim_status/extkeys/paths,
  ./test_helpers


procSuite "multiaccount":

  test "entropy strength":
    let entropyStrength = mnemonicPhraseLengthToEntropyStrength(12)
    assert entropyStrength.int == 128
  
  test "generate and derive accounts, store derived accounts":
    let
      gntr = Generator.new()
      passphrase = ""
      paths = @[PATH_WALLET_ROOT, PATH_DEFAULT_WALLET, PATH_WHISPER]
      gndAccountInfosResult = gntr.generateAndDeriveAddresses(12, 1, passphrase,
        paths)

    assert gndAccountInfosResult.isOk

    let
      gndAccountInfos = gndAccountInfosResult.get
      gndAccountInfo = gndAccountInfos[0]
    assert len(gndAccountInfo.derived) == 3

    echo "Generated account mnemonic: ", gndAccountInfo.mnemonic.string

    let
      gndImportedAccInfoResult = gntr.importMnemonic(gndAccountInfo.mnemonic, passphrase)
    
    assert gndImportedAccInfoResult.isOk

    let gndImportedAccInfo = gndImportedAccInfoResult.get
      
    assert gndImportedAccInfo.mnemonic.string.toBytes ==
      gndAccountInfo.mnemonic.string.toBytes

    let
      password = "qwerty"
      dir = "test_accounts"

    createDir(dir)

    let storeDerivedAccsResult = gntr.storeDerivedAccounts(gndAccountInfo.id, paths, password, dir,
        workfactor = 100)

    assert storeDerivedAccsResult.isOk

    let
      storeDerivedAccs = storeDerivedAccsResult.get
      chatAddress = storeDerivedAccs[2].address
      loadAccResult = gntr.loadAccount(chatAddress, password, dir)

    assert loadAccResult.isOk, "failed loading account"

    let loadAcc = loadAccResult.get

    assert loadAcc.address == chatAddress

    removeDir(dir)

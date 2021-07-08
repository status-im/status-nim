import # nim libs
  json, options, os, unittest

import # vendor libs
  chronos, confutils, json_serialization, sqlcipher, web3/conversions as web3_conversions

import # nim-status libs
  ../nim_status/[accounts, client, conversions, database, settings],
  ./test_helpers

procSuite "client":
  asyncTest "client":

    let dataDir = currentSourcePath.parentDir() / "build" / "data"

    let statusObj = StatusObject.new(dataDir)

    var account:PublicAccount = PublicAccount(
      name: "Test",
      loginTimestamp: 1.some,
      identicon: "data:image/png;base64,something",
      keycardPairing: "",
      keyUid: "0x1234"
    )

    statusObj.saveAccount(account)
    statusObj.updateAccountTimestamp(1, "0x1234")
    let accounts = statusObj.getAccounts()
    check:
      statusObj.dataDir == dataDir
      accounts[0].keyUid == "0x1234"

    let password = "qwerty"
    statusObj.login(account.keyUid, password)
    let settingsStr = """{
      "address": "0x1122334455667788990011223344556677889900",
      "chaos-mode": true,
      "networks/current-network": "mainnet",
      "dapps-address": "0x1122334455667788990011223344556677889900",
      "eip1581-address": "0x1122334455667788990011223344556677889900",
      "installation-id": "ABC-DEF-GHI",
      "key-uid": "XYZ",
      "latest-derived-path": 0,
      "networks/networks": [{"id":"mainnet_rpc","etherscan-link":"https://etherscan.io/address/","name":"Mainnet with upstream RPC","config":{"NetworkId":1,"DataDir":"/ethereum/mainnet_rpc","UpstreamConfig":{"Enabled":true,"URL":"wss://mainnet.infura.io/ws/v3/7230123556ec4a8aac8d89ccd0dd74d7"}}}],
      "name": "test",
      "photo-path": "ABXYZC",
      "preview-privacy?": false,
      "public-key": "0x123",
      "signing-phrase": "ABC DEF GHI",
      "wallet-root-address": "0x1122334455667788990011223344556677889900"
    }"""
    let settingsObj = Json.decode(settingsStr, Settings, allowUnknownFields = true)

    let nodeConfig = %* {"config": 1}
    statusObj.createSettings(settingsObj, nodeConfig)
    let dbSettings = statusObj.getSettings()
    check:
      dbSettings.keyUID == settingsObj.keyUID


    statusObj.close()
    removeDir(datadir)

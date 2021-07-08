import # nim libs
  std/[json, options, os, unittest]

import # vendor libs
  chronos, json_serialization, json_serialization/std/options as json_options,
  options, sqlcipher, web3/conversions

import # nim-status libs
  ../nim_status/[callrpc, database, settings],
  ../nim_status/migrations/sql_scripts_app,
  ./test_helpers

procSuite "callrpc":
  asyncTest "callrpc":
    let password = "qwerty"
    let path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)
    let db = initializeDB(path, password)

    let settingsStr = """{
      "address": "0x1122334455667788990011223344556677889900",
      "networks/current-network": "mainnet_rpc",
      "dapps-address": "0x1122334455667788990011223344556677889900",
      "eip1581-address": "0x1122334455667788990011223344556677889900",
      "installation-id": "ABC-DEF-GHI",
      "key-uid": "XYZ",
      "latest-derived-path": 0,
      "networks/networks": [{"id":"mainnet_rpc","etherscan-link":"https://etherscan.io/address/","name":"Mainnet with upstream RPC","config":{"NetworkId":1,"DataDir":"/ethereum/mainnet_rpc","UpstreamConfig":{"Enabled":true,"URL":"wss://mainnet.infura.io/ws/v3/7230123556ec4a8aac8d89ccd0dd74d7"}}}],
      "photo-path": "ABXYZC",
      "preview-privacy?": false,
      "public-key": "0x123",
      "signing-phrase": "ABC DEF GHI"
    }"""

    let settingsObj = JSON.decode(settingsStr, Settings, allowUnknownFields = true)
    let web3Obj = newWeb3(settingsObj)
    let rGasPrice = callRPC(web3Obj, eth_gasPrice, %[])

    check:
      rGasPrice.getStr()[0..1] == "0x"

    let rEthSign = callRPC(web3Obj, "eth_sign", %[])

    check:
      rEthSign["code"].getInt == -32601
      rEthSign["message"].getStr == "the method eth_sign does not exist/is not available"

    let rSendTransaction = callRPC(web3Obj, "eth_sendTransaction", %* [%*{"from": "0x0000000000000000000000000000000000000000", "to": "0x0000000000000000000000000000000000000000", "value": "123"}])

    check:
      rSendTransaction["code"].getInt == -32601
      rSendTransaction["message"].getStr == "the method eth_sendTransaction does not exist/is not available"

    db.close()
    removeFile(path)

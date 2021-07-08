import # nim libs
  json, options, os, unittest

import # vendor libs
  chronos, json_serialization, sqlcipher, web3/conversions

import # nim-status libs
  ../nim_status/[database, tokens],
  ./test_helpers

procSuite "tokens":
  asyncTest "tokens":
    let password = "qwerty"
    let path = currentSourcePath.parentDir() & "/build/my.db"
    removeFile(path)
    let db = initializeDB(path, password)

    let tokensStr = """{
      "address": "0x1122334455667788990011223344556677889900",
      "name": "Status",
      "symbol": "SNT",
      "decimals": 18,
      "color": "#eeeeee"
    }"""

    let tokensObj = JSON.decode(tokensStr, Token, allowUnknownFields = true)

    db.addCustomToken(tokensObj)

    var token_list = db.getCustomTokens()

    check:
      token_list.len == 1

    let token = token_list[0]

    check:
      $token.address == "0x1122334455667788990011223344556677889900"
      token.name == "Status"
      token.symbol == "SNT"
      token.decimals == 18
      token.color == "#eeeeee"

    db.deleteCustomToken(token.address)

    token_list = db.getCustomTokens()

    check:
      token_list.len == 0

    db.close()
    removeFile(path)

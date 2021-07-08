import # nim libs
  os, unittest

import # vednor libs
  chronos, eth/[keys, p2p]

import # nim-status libs
  ../nim_status/account,
  ./test_helpers, ./test_utils

procSuite "account":
  asyncTest "account":
    resetDirectories() # Recreates the data and nobackup dir
    init()

    # Single RNG instance for the application - will be seeded on construction
    # and avoid using system resources (such as urandom) after that
    var rng = keys.newRng()

    let account = createAccount(rng)
    let pubKey = derivePubKeyFromPrivateKey(account.privateKey)
    let signature = signMessage(account.privateKey, "Hello world")

    check:
      account.address != ""
      account.publicKey != ""
      account.privateKey != ""
      account.publicKey == pubKey
      signature != ""

    if not defined(windows):
      removeDirectories()

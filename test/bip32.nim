import # nim libs
  unittest

import # vendor libs
  chronos, eth/keys, secp256k1, stew/[results]

import # nim-status libs
  ../nim_status/extkeys/[hdkey, mnemonic, types],
  ./test_helpers

procSuite "bip32":
  asyncTest "bip32":
    let seed = mnemonicSeed(Mnemonic "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside")
    var extPrivKResult = newMaster(seed)

    assert extPrivKResult.isOK

    let extPrivKey = extPrivKResult.get

    # This derivation path will generate a private key corresponding to wallet i=0
    var pk = derive(extPrivKey, KeyPath "m/44'/60'/0'/0/0").get()

    check:
      $ pk.secretKey == "ff1e68eb7bf2f48651c47ef0177eb815857322257c5894bb4cfd1176c9989314"

    # This derivation path will generate a status public key
    pk = derive(extPrivKey, KeyPath "m/43'/60'/1581'/0'/0").get()

    check:
      $ pk.secretKey == "38ac4da490b5c48a06d0a2fe7900c56b6639b88f6f71303590f28047411981c2"
      $ pk.secretKey.toPublicKey() == "04ac5a45f2a90052cee10b22b74832f2deb814d58e35aa3f01a249160615a238aef3a34ba86e1817fc8c5a6e93e3c5f159f6c46e922c85d47bafc4b78e07718279"

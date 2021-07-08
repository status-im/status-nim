import # std libs
  std/strformat

import # vendor libs
  nimcrypto/[sha2, hash, hmac], json_serialization, stew/results

import # nim-status libs
  ./alias, ./extkeys/types

export KeySeed, Mnemonic, SecretKeyResult, KeyPath



type Account* = ref object
  keyUid*: string
  address*: string
  publicKey*: string
  privateKey*: string
  # TODO remove {.dontSerialize.}
  path* {.dontSerialize.}: KeyPath

type MultiAccount* = object
  # TODO remove {.dontSerialize.}
  mnemonic* {.dontSerialize.}: Mnemonic
  accounts*: seq[Account]
  keyseed* {.dontSerialize.}: KeySeed

proc `$`*(acc: Account): string =
  echo "Account begin"
  echo "Addr: ", acc.address
  echo "PrivateKey: ", acc.privateKey
  echo "PublicKey: ", acc.publicKey
  echo "Path: ", acc.path.string
  echo "Account end"

proc toDisplayString*(account: Account): string =
  let name = account.publicKey.generateAlias()
  fmt"{name} ({account.keyUid})"

proc toDisplayString*(multiAcc: MultiAccount): string =
  multiAcc.accounts[2].toDisplayString()



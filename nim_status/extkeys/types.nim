import # std libs
  std/typetraits

import # vendor libs
  secp256k1, stew/results

type
  Mnemonic* = distinct string

  KeySeed* = distinct seq[byte]

  KeystorePass* = string

  KeyPath* = distinct string

  PathLevel* = distinct uint32

  PathLevelResult* = Result[PathLevel, string]

  ExtendedPrivKey* = object
    secretKey*: SkSecretKey
    chainCode*: seq[byte]

  ExtendedPrivKeyResult* = Result[ExtendedPrivKey, string]

  SecretKeyResult* = SkResult[SkSecretKey]

proc `==`*(a, b: KeyPath): auto = distinctBase(a) == distinctBase(b)

proc `$`*(k: KeyPath): auto = distinctBase(k)

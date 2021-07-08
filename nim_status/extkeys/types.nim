import secp256k1
import stew/[results]

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

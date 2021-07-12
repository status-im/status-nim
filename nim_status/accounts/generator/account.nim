import # vendor libs
  chronicles, eth/keys, eth/keyfile/uuid, nimcrypto/sha2, secp256k1,
  stew/byteutils

import # nim-status libs
  ../../extkeys/types

type
  Account* = ref object
    secretKey*: SkSecretKey
    extendedKey*: ExtendedPrivKey

  AccountInfo* = ref object of RootObj
    publicKey*: string
    address*: string

  IdentifiedAccountInfo* = ref object of AccountInfo
    id*: UUID
    keyUid*: string

  GeneratedAccountInfo* = ref object of IdentifiedAccountInfo
    mnemonic*: Mnemonic
  
  GeneratedAndDerivedAccountInfo* = ref object of GeneratedAccountInfo
    derived*: seq[AccountInfo]

proc toAccountInfo*(a: Account): AccountInfo =
  let
    publicKey = a.secretKey.toPublicKey()
    address = PublicKey(publicKey).toChecksumAddress()
  
  AccountInfo(publicKey: "0x" & $publicKey, address: address)

proc toIdentifiedAccountInfo*(a: Account, id: UUID): IdentifiedAccountInfo =
  let
    info = a.toAccountInfo()
    publicKeyResult = SkPublicKey.fromHex(info.publicKey)

  if publicKeyResult.isErr:
    error "Error getting keyUid from public key", error=publicKeyResult.error
    return

  let
    publicKey = publicKeyResult.get
    hash = sha256.digest(publicKey.toRaw())
    keyUid = "0x" & toHex(toOpenArray(hash.data, 0, len(hash.data) - 1))

  IdentifiedAccountInfo(publicKey: info.publicKey, address: info.address,
    id: id, keyUid: keyUid)

proc toGeneratedAccountInfo*(a: Account, id: UUID,
  mnemonic: Mnemonic): GeneratedAccountInfo =

  let idInfo = a.toIdentifiedAccountInfo(id)

  GeneratedAccountInfo(id: idInfo.id, keyUid: idInfo.keyUid,
    publicKey: idInfo.publicKey, address: idInfo.address, mnemonic: mnemonic)

proc toGeneratedAndDerived*(a: GeneratedAccountInfo,
  derived: seq[AccountInfo]): GeneratedAndDerivedAccountInfo =

  GeneratedAndDerivedAccountInfo(mnemonic: a.mnemonic, id: a.id,
    keyUid: a.keyUid, publicKey: a.publicKey, address: a.address,
    derived: derived)

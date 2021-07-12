import # std libs
  std/[json, options, strutils, times]

import # vendor libs
  chronicles, json_serialization, json_serialization/std/options as json_options,
  secp256k1, stew/byteutils, sqlcipher, web3/ethtypes

import # nim_status libs
  ./extkeys/types as key_types, ./settings/types

from ./tx_history/types as tx_history_types import TxType

# needed because nim-sqlcipher calls toDbValue/fromDbValue which does not have
# json_serialization/std/options imported 
export json_options

const dtFormat = "yyyy-MM-dd HH:mm:ss fffffffff"

proc parseAddress*(address: string): Address =
  Address.fromHex(address)

proc toDbValue*[T: Address](val: T): DbValue =
  DbValue(kind: sqliteText, strVal: $val)

proc toDbValue*(val: DateTime): DbValue =
  DbValue(kind: sqliteText, strVal: val.format(dtFormat))

proc toDbValue*(val: JsonNode): DbValue =
  DbValue(kind: sqliteText, strVal: $val)

proc toDbValue*(val: KeyPath): DbValue =
  DbValue(kind: sqliteText, strVal: val.string)

proc toDbValue*[T: seq[auto]](val: T): DbValue =
  DbValue(kind: sqliteText, strVal: Json.encode(val))

proc toDbValue*(val: SkPublicKey): DbValue =
  DbValue(kind: sqliteBlob, blobVal: ($val).hexToSeqByte)

proc toDbValue*(val: TxType): DbValue =
  DbValue(kind: sqliteText, strVal: $val)

proc fromDbValue*(val: DbValue, T: typedesc[Address]): Address =
  val.strVal.parseAddress

proc fromDbValue*(val: DbValue, T: typedesc[DateTime]): DateTime =
  val.strVal.parse(dtFormat)

proc fromDbValue*(val: DbValue, T: typedesc[JsonNode]): JsonNode =
  val.strVal.parseJson

proc fromDbValue*(val: DbValue, T: typedesc[KeyPath]): KeyPath =
  KeyPath val.strVal

proc fromDbValue*(val: DbValue, T: typedesc[SkPublicKey]): SkPublicKey =
  let pubKeyResult = SkPublicKey.fromRaw(val.blobVal)
  if pubKeyResult.isErr:
    # TODO: implement chronicles in nim-status (in the tests)
    echo "error converting db value to public key, error: " &
      $(pubKeyResult.error)
    return
  pubKeyResult.get

proc fromDbValue*(val: DbValue, T: typedesc[TxType]): TxType =
  parseEnum[TxType](val.strVal)

proc fromDbValue*[T: seq[auto]](val: DbValue, _: typedesc[T]): T =
  Json.decode(val.strVal, T, allowUnknownFields = true)

# Strips leading zeroes and appends 0x prefix
proc intToHex*(n: int): string = 
  if n == 0:
    return "0x0"
  var s = n.toHex
  s.removePrefix({'0'})
  result = "0x" & s


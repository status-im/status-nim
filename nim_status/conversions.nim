import # std libs
  std/[json, options, strutils]

import # vendor libs
  json_serialization, json_serialization/std/options as json_options, sqlcipher,
  web3/ethtypes, stew/byteutils

import # nim_status libs
  ./settings/types

from ./tx_history/types as tx_history_types import TxType

# needed because nim-sqlcipher calls toDbValue/fromDbValue which does not have
# json_serialization/std/options imported 
export json_options

proc parseAddress*(strAddress: string): Address =
  fromHex(Address, strAddress)

proc toDbValue*[T: Address](val: T): DbValue =
  DbValue(kind: sqliteText, strVal: $val)

proc toDbValue*(val: JsonNode): DbValue =
  DbValue(kind: sqliteText, strVal: $val)

proc toDbValue*[T: seq[auto]](val: T): DbValue =
  DbValue(kind: sqliteText, strVal: Json.encode(val))

proc toDbValue*(val: TxType): DbValue =
  DbValue(kind: sqliteText, strVal: $val)

proc fromDbValue*(val: DbValue, T: typedesc[JsonNode]): JsonNode = val.strVal.parseJson

proc fromDbValue*(val: DbValue, T: typedesc[TxType]): TxType = parseEnum[TxType](val.strVal)

proc fromDbValue*(val: DbValue, T: typedesc[Address]): Address = val.strVal.parseAddress

proc fromDbValue*[T: seq[auto]](val: DbValue, _: typedesc[T]): T =
  Json.decode(val.strVal, T, allowUnknownFields = true)

# Strips leading zeroes and appends 0x prefix
proc intToHex*(n: int): string = 
  if n == 0:
    return "0x0"
  var s = n.toHex
  s.removePrefix({'0'})
  result = "0x" & s


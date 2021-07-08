import # vendor libs
  json_serialization

import # nim-status libs
  ../../../nim_status/extkeys/types

proc writeValue*(w: var JsonWriter, m: Mnemonic) {.inline.} =
  w.writeValue m.string

proc readValue*(r: var JsonReader, m: var Mnemonic) {.inline.} =
  m = Mnemonic r.readValue(string)
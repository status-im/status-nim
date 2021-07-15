import nimcrypto, re, strutils, unicode, web3/ethtypes

const hexPattern = "^[0-9a-f]+$"

proc isHexString*(str: string): bool =
  let reHex = re(hexPattern, {reIgnoreCase})
  str.len > 3 and
  str.len mod 2 == 0 and
  str[0..1] == "0x" and
  match(str[2..^1], reHex)

proc isPubKey*(str: string): bool =
  let reHex = re(hexPattern, {reIgnoreCase})
  str.len == 132 and
  str[0..3] == "0x04" and
  match(str[2..^1], reHex)

proc hashMessage*(message: string): string =
  ## hashMessage calculates the hash of a message to be safely signed by the keycard.
  ## The hash is calulcated as
  ##  keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
  ## This gives context to the signed message and prevents signing of transactions.
  var msg = message
  if isHexString(msg):
    try:
      msg = parseHexStr(msg[2..^1])
    except:
      discard
  const END_OF_MEDIUM = Rune(0x19).toUTF8
  const prefix = END_OF_MEDIUM & "Ethereum Signed Message:\n"
  "0x" & toLower($keccak_256.digest(prefix & $(msg.len) & msg))

proc indexOf*[T](s: seq[T], item: T): int =
  var i = 0
  for i in 0..s.len:
    if s[i] == item:
      return i
  return -1

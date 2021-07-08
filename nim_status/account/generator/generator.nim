import # std libs
  std/[json, os]

import # vendor libs
  eth/[keyfile/keyfile, keys], nimcrypto/[sha2, pbkdf2, hash, hmac],
  json_serialization, secp256k1, stew/[results, byteutils]

import # nim-status libs
  ../../extkeys/[hdkey, mnemonic, types], ../../multiaccount, ./utils

export utils

const
    MIN_SEED_BYTES = 16 # 128 bits
      # MinSeedBytes is the minimum number of bytes allowed for a seed to a master node.
    MAX_SEED_BYTES = 64 # 512 bits
      # MaxSeedBytes is the maximum number of bytes allowed for a seed to a master node.

proc toKeyUid(publicKey: PublicKey): string =
  let hash = sha256.digest(publicKey.toRaw())
  "0x" & toHex(toOpenArray(hash.data, 0, len(hash.data) - 1))

proc buildAccount(privateKey: PrivateKey): Account =
  var acc = Account()
  acc.privateKey = $privateKey
  let publicKey = privateKey.toPublicKey()
  acc.publicKey = "0x04" & $publicKey
  acc.address = publicKey.toAddress()
  # let skResult = PublicKey.fromHex(acc.publicKey)
  acc.keyUid = publicKey.toKeyUid()
  # acc.keyUid = PublicKey.fromHex(acc.publicKey).toKeyUid()

  return acc

proc deriveAccounts*(multiAcc: MultiAccount, paths: seq[KeyPath]): seq[Account] =
  var accounts: seq[Account]
  for p in paths:
    let skResult = derive(multiAcc.keySeed, p)
    var acc = buildAccount(PrivateKey(skResult.get()))
    acc.path = p
    accounts.add(acc)
  return accounts

proc importMnemonic*(mnemonicPhrase: Mnemonic, bip39Passphrase: string): MultiAccount =
  let seed = mnemonicSeed(mnemonicPhrase, bip39Passphrase)
  # Ensure seed is within expected limits
  let lseed = openArray[byte](seed).len
  if lseed < MIN_SEED_BYTES or lseed > MAX_SEED_BYTES:
    return MultiAccount()

  return MultiAccount(mnemonic: mnemonicPhrase,
         keyseed: seed)

proc generateAndDeriveAccounts*(mnemonicPhraseLength: int, n: int,
  bip39Passphrase: string, paths: seq[KeyPath]): seq[MultiAccount] =

  let entropyStrength = mnemonicPhraseLengthToEntropyStrength(mnemonicPhraseLength)
  var multiAccounts = newSeq[MultiAccount]()
  for i in 0..<n:
    let phrase = mnemonicPhrase(entropyStrength, Language.English)
    var multiAcc = importMnemonic(phrase, bip39Passphrase)
    # let masterSecKey = deriveMaster(multi)
    # multiAcc.pubkey = 
    multiAcc.accounts = deriveAccounts(multiAcc,  paths)
    multiAccounts.add(multiAcc)

  return multiAccounts


proc importMnemonicAndDeriveAccounts*(mnemonicPhrase: Mnemonic, bip39Passphrase: string, paths: seq[KeyPath]): MultiAccount =
  var multiAcc = importMnemonic(mnemonicPhrase, bip39Passphrase)
  multiAcc.accounts = deriveAccounts(multiAcc,  paths)

  return multiAcc

proc storeDerivedAccounts*(multiAcc: MultiAccount, password: string,
  dir: string = "", version: int = 3, cryptkind: CryptKind = AES128CTR,
  kdfkind: KdfKind = PBKDF2, workfactor: int = 0) =

  var workfactorFinal = workfactor
  when not defined(release):
    # reduce the account creation time by a factor of 5 for debug builds only
    if workfactorFinal == 0: workfactorFinal = 100

  for acc in multiAcc.accounts:
    let privateKey = acc.privateKey
    let keyFileJson = createKeyFileJson(PrivateKey.fromHex(privateKey).get(), password, version, cryptkind, kdfkind, workfactorFinal)

    writeFile(dir / acc.address, $keyFileJson.get())


proc loadAccount*(address: string, password: string, dir: string = ""): Account =
  let json = parseFile(dir / address)
  let privateKey = decodeKeyFileJson(json, password)

  return buildAccount(privateKey.get())

# NewMaster creates new master node, root of HD chain/tree.
# Both master and child nodes are of ExtendedKey type, and all the children derive from the root node.
import # std libs
  std/strformat

import # vendor libs
  eth/keys, nimcrypto/hmac, secp256k1, stew/[results, byteutils]

import # nim-status libs
  ./utils, ./paths, ./types

const
  masterSecret*: string = "Bitcoin seed"
  MIN_SEED_BYTES = 16 # 128 bits
      # MinSeedBytes is the minimum number of bytes allowed for a seed to a master node.
  MAX_SEED_BYTES = 64 # 512 bits
    # MaxSeedBytes is the maximum number of bytes allowed for a seed to a master node.

proc child(self: ExtendedPrivKey, child: PathLevel): ExtendedPrivKeyResult =
  var hctx: HMAC[sha512]
  hctx.init(self.chainCode)
  if child.isNonHardened():
    hctx.update(self.secretKey.toPublicKey().toRawCompressed())
  else:
    hctx.update([0.byte])
    hctx.update(self.secretKey.toRaw())
  hctx.update(child.toBEBytes());
  let hmacResult = hctx.finish();

  var secretKey = hmacResult.data[0..31]
  let chainCode = hmacResult.data[32..63]

  var pk = self.secretKey.toRaw()[0..^1]
  var sk = SkSecretKey.fromRaw(secretKey)
  if sk.isOk:
    let tweakResult = tweakAdd(sk.get(), pk)
    if tweakResult.isErr: return err($tweakResult.error())
    return ok(ExtendedPrivKey(
      secretKey: sk.get(),
      chainCode: chainCode
    ))

  err($sk.error())

proc derive*(k: ExtendedPrivKey, path: KeyPath): ExtendedPrivKeyResult =
  var extKey = k
  for child in path.pathNodes:
    if child.isErr(): return ExtendedPrivKeyResult.err(child.error())

    let childResult = extKey.child(child.get)
    if childResult.isErr(): return ExtendedPrivKeyResult.err(childResult.error())
    extKey = childResult.get

  ok(extKey)

proc newMaster*(seed: Keyseed): ExtendedPrivKeyResult =
  # NewMaster creates new master node, root of HD chain/tree.
  # Both master and child nodes are of ExtendedKey type, and all the children derive from the root node.
  let lseed = openArray[byte](seed).len
  if lseed < MIN_SEED_BYTES or lseed > MAX_SEED_BYTES:
    return ExtendedPrivKeyResult.err(
      fmt"the recommended size of seed is {MIN_SEED_BYTES}-{MAX_SEED_BYTES} bits"
    )

  splitHMAC(string.fromBytes(openArray[byte](seed)), masterSecret)

proc toExtendedKey*(secretKey: SkSecretKey): ExtendedPrivKeyResult =
  let extPrivKey = ExtendedPrivKey(secretKey: secretKey)
  ExtendedPrivKeyResult.ok(extPrivKey)

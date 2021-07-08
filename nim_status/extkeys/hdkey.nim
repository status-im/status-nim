import # vendor libs
  eth/keys, nimcrypto/[sha2, pbkdf2, hash, hmac], secp256k1,
  stew/[results, byteutils]

import # nim-status libs
  ./utils, ./paths, ./types

const masterSecret*: string = "Bitcoin seed"

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

# proc deriveMaster*(seed: Keyseed): SecretKeyResult =
#   let extPrivK = splitHMAC(string.fromBytes(openArray[byte](seed)), masterSecret).get()
#   ok(extPrivK.secretKey)

proc derive*(seed: Keyseed, path: KeyPath): SecretKeyResult =
  var extPrivK = splitHMAC(string.fromBytes(openArray[byte](seed)), masterSecret).get()

  for child in path.pathNodes:
    if child.isErr(): return err(child.error().cstring)

    let r = extPrivK.child(child.get())
    if r.isErr(): return err(r.error().cstring)
    extPrivK = r.get()

  ok(extPrivK.secretKey)
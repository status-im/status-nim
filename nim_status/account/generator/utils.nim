import # nim-status libs
  ../../extkeys/mnemonic

# MnemonicPhraseLengthToEntropyStrength returns the entropy strength for a given mnemonic length
proc mnemonicPhraseLengthToEntropyStrength*(length: int): EntropyStrength =
  if length < 12 or length > 24 or length mod 3 != 0:
    return EntropyStrength(0)

  let bitsLength = length * 11
  let checksumLength = bitsLength mod 32

  return EntropyStrength(bitsLength - checksumLength)

# TODO: Add ValidateKeystoreExtendedKey
# https://github.com/status-im/status-go/blob/287e5cdf79fc06d5cf5c9d3bd3a99a1df1e3cd10/account/generator/utils.go#L24-L34

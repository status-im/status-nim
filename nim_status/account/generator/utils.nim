import # nim-status libs
  ../../extkeys/mnemonic

# MnemonicPhraseLengthToEntropyStrength returns the entropy strength for a given mnemonic length
proc mnemonicPhraseLengthToEntropyStrength*(length: int): EntropyStrength =
  if length < 12 or length > 24 or length mod 3 != 0:
    return EntropyStrength(0)

  let bitsLength = length * 11
  let checksumLength = bitsLength mod 32

  return EntropyStrength(bitsLength - checksumLength)
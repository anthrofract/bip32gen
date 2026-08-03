# bip39gen

BIP-39 mnemonic generator combining multiple independent entropy sources.

## Usage

```text
Generate a BIP-39 mnemonic from multiple entropy sources

Usage: bip39gen [OPTIONS]

Options:
      --os <OS_ENTROPY>
          Use entropy from the operating system's cryptographic random number generator [default: true] [possible values: true, false]
      --dice <DICE_ENTROPY>
          Use entropy from interactive dice rolls [default: true] [possible values: true, false]
      --dice-sides <DICE_SIDES>
          Number of sides on each die (defaults to 6)
      --openpgp-card <OPENPGP_CARD_ENTROPY>
          Use entropy from an OpenPGP smart card such as a YubiKey [default: true] [possible values: true, false]
      --words <WORDS>
          Number of words in the generated mnemonic [default: 12] [possible values: 12, 15, 18, 21, 24]
      --pgp-pubkey <PATH>
          OpenPGP public key used to encrypt the mnemonic with GPG
  -o, --output <PATH>
          Output path (defaults to seed.txt or seed.txt.asc when encrypted)
  -f, --force
          Overwrite an existing output file
  -h, --help
          Print help
  -V, --version
          Print version
```

## Example run

```text
❯ bip39gen --pgp-pubkey pubkey.asc
🚨 WARNING: Run this program only in a trusted, ephemeral, offline environment, such as in Tails OS.
🏁 Generating a 12-word mnemonic from 128 bits (16 bytes) of entropy per source.
💻 Collecting 128 bits of OS entropy...
💳 Collecting 128 bits of OpenPGP smart card entropy...
🎲 Collecting 128 bits of dice entropy using d6 rolls...
🚨 WARNING: Dice rolls are visible and may remain in terminal scrollback or session logs.
🎲 Enter dice rolls separated by spaces:
🎲 [0 d6 rolls entered of ~50.182]:  1 2 3 4 5 6 1 2 3 4 5 6 1 2 3 4 5 6 1 2 3 4 5 6 1 2 3 4 5 6 1 2 3 4 5 6 1 2 3 4 5 6 1 2 3 4 5 6 1 2 3 4 5 6
🎲 [50 d6 rolls entered of ~50.182]: Finished.
🔀 Combining entropy from 3 sources to produce 128 bits of final entropy...
📄 Constructing mnemonic...
🔒 Encrypting seed phrase with GPG...
✅ Wrote encrypted mnemonic to 'seed.txt.asc'.
```

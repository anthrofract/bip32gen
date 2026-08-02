# bip39gen

BIP-39 mnemonic generator combining multiple independent entropy sources.

## Usage

```text
Generate a BIP-39 mnemonic from multiple entropy sources

Usage: bip39gen [OPTIONS]

Options:
      --os <OS_ENTROPY>            Use entropy from the operating system's cryptographic random number generator [default: true] [possible values: true, false]
      --dice <DICE_ENTROPY>        Use entropy from interactive dice rolls [default: true] [possible values: true, false]
      --dice-sides <DICE_SIDES>    Number of sides on each die (defaults to 6)
      --yubikey <YUBIKEY_ENTROPY>  Use entropy from a YubiKey [default: true] [possible values: true, false]
      --words <WORDS>              Number of words in the generated mnemonic [default: 12] [possible values: 12, 18, 24]
      --gpg-pubkey <PATH>          OpenPGP public key used to encrypt the mnemonic with GPG
  -o, --output <PATH>              Output path (defaults to seed.txt or seed.txt.asc when encrypted)
  -f, --force                      Overwrite an existing output file
  -h, --help                       Print help
  -V, --version                    Print version
```

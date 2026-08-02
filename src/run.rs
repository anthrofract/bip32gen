use std::{fmt::Write, path::Path};

use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::cli::{Config, WordCount};

pub(crate) fn run(config: Config) -> anyhow::Result<()> {
    let entropy = collect_entropy(&config)?;
    let mnemonic = generate_mnemonic(&entropy)?;
    write_output(&config, &mnemonic)
}

fn collect_entropy(config: &Config) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let byte_count = config.words.entropy_bytes();
    let mut sources = Vec::with_capacity(3);

    if config.os_entropy {
        sources.push(("os", collect_os_entropy(byte_count)?));
    }
    if let Some(sides) = config.dice_entropy {
        sources.push(("dice", collect_dice_entropy(sides, byte_count * 8)?));
    }
    if config.yubikey_entropy {
        sources.push(("yubikey", collect_yubikey_entropy(byte_count)?));
    }

    Ok(combine_entropy(&sources, byte_count))
}

fn collect_os_entropy(_byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    todo!()
}

fn collect_dice_entropy(_sides: u32, _bit_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    todo!()
}

fn collect_yubikey_entropy(_byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    todo!()
}

fn combine_entropy(
    _sources: &[(&str, Zeroizing<Vec<u8>>)],
    _byte_count: usize,
) -> Zeroizing<Vec<u8>> {
    todo!()
}

fn generate_mnemonic(_entropy: &[u8]) -> anyhow::Result<Mnemonic> {
    todo!()
}

fn write_output(config: &Config, mnemonic: &Mnemonic) -> anyhow::Result<()> {
    let words = mnemonic.words();
    let capacity = words.clone().map(|word| word.len() + 1).sum();
    let mut seed_phrase = Zeroizing::new(String::with_capacity(capacity));
    for word in words {
        writeln!(&mut *seed_phrase, "{word}")?;
    }

    if let Some(gpg_pubkey) = &config.gpg_pubkey {
        let encrypted = encrypt_with_gpg(&seed_phrase, gpg_pubkey)?;
        write_file(&config.output_path, &encrypted, config.overwrite)
    } else {
        write_file(
            &config.output_path,
            seed_phrase.as_bytes(),
            config.overwrite,
        )
    }
}

fn encrypt_with_gpg(_seed_phrase: &str, _gpg_pubkey: &Path) -> anyhow::Result<Vec<u8>> {
    todo!()
}

fn write_file(_output_path: &Path, _contents: &[u8], _overwrite: bool) -> anyhow::Result<()> {
    todo!()
}

impl WordCount {
    fn entropy_bytes(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::Eighteen => 24,
            Self::TwentyFour => 32,
        }
    }
}

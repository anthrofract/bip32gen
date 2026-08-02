use std::{
    fmt::Write as _,
    fs::OpenOptions,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{Context, bail};
use bip39::Mnemonic;
use log::info;
use zeroize::Zeroizing;

use crate::cli::{Config, WordCount};

pub(crate) fn run(config: Config) -> anyhow::Result<()> {
    let entropy = collect_entropy(&config)?;
    let mnemonic = generate_mnemonic(&entropy)?;
    write_output(&config, &mnemonic)
}

fn collect_entropy(config: &Config) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!("Collecting entropy");

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

fn generate_mnemonic(entropy: &[u8]) -> anyhow::Result<Mnemonic> {
    info!("Generating BIP-39 mnemonic");
    Mnemonic::from_entropy(entropy).context("failed to generate BIP-39 mnemonic")
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

fn encrypt_with_gpg(seed_phrase: &str, gpg_pubkey: &Path) -> anyhow::Result<Vec<u8>> {
    info!("Encrypting seed phrase with GPG");

    let mut child = Command::new("gpg")
        .args([
            "--no-options",
            "--batch",
            "--no-tty",
            "--armor",
            "--always-trust",
            "--encrypt",
            "--recipient-file",
        ])
        .arg(gpg_pubkey)
        .args(["--output", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start GPG")?;

    let write_result = child
        .stdin
        .take()
        .context("failed to open GPG stdin")?
        .write_all(seed_phrase.as_bytes());
    if let Err(error) = write_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("failed to send seed phrase to GPG");
    }

    let output = child.wait_with_output().context("failed to wait for GPG")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("GPG encryption failed with status {}", output.status);
        }
        bail!("GPG encryption failed: {stderr}");
    }

    Ok(output.stdout)
}

fn write_file(output_path: &Path, contents: &[u8], overwrite: bool) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options
        .open(output_path)
        .with_context(|| format!("failed to open output file '{}'", output_path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write output file '{}'", output_path.display()))?;

    info!("Output written successfully to '{}'", output_path.display());
    Ok(())
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

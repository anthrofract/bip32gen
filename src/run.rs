use std::{
    fs::OpenOptions,
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{Context, bail};
use bip39::Mnemonic;
use log::info;

use crate::secret_string::SecretString;

pub(crate) fn run(config: crate::cli::Config) -> anyhow::Result<()> {
    let byte_count = config.words.entropy_bytes();
    info!(
        "Generating a {}-word mnemonic from {} bits ({} bytes) of entropy.",
        config.words.word_count(),
        byte_count * 8,
        byte_count,
    );

    let entropy = crate::entropy::collect_entropy(&config)?;
    let mnemonic = construct_mnemonic(&entropy)?;
    write_output(&config, &mnemonic)
}

fn construct_mnemonic(entropy: &[u8]) -> anyhow::Result<Mnemonic> {
    info!("Constructing mnemonic...");
    Mnemonic::from_entropy(entropy).context("failed to generate BIP-39 mnemonic")
}

fn write_output(config: &crate::cli::Config, mnemonic: &Mnemonic) -> anyhow::Result<()> {
    let mut seed_phrase = SecretString::new();
    for word in mnemonic.words() {
        seed_phrase.push_str(word)?;
        seed_phrase.push_str("\n")?;
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

    info!(
        "Successfully wrote mnemonic to '{}'.",
        output_path.display()
    );
    Ok(())
}

impl crate::cli::WordCount {
    fn word_count(self) -> usize {
        match self {
            Self::Twelve => 12,
            Self::Eighteen => 18,
            Self::TwentyFour => 24,
        }
    }
}

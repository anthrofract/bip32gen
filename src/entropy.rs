use std::{io, process::Command};

use anyhow::{Context, bail, ensure};
use log::info;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{Config, WordCount};

pub(crate) fn collect_entropy(config: &Config) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let byte_count = config.words.entropy_bytes();
    let mut sources = Vec::with_capacity(3);

    if config.os_entropy {
        sources.push(collect_os_entropy(byte_count)?);
    }
    if config.yubikey_entropy {
        sources.push(collect_yubikey_entropy(byte_count)?);
    }
    if let Some(sides) = config.dice_entropy {
        sources.push(collect_dice_entropy(byte_count, sides)?);
    }

    combine_entropy(&sources, byte_count)
}

fn collect_os_entropy(byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!("Collecting {byte_count} bytes of OS entropy");

    let mut entropy = Zeroizing::new(vec![0; byte_count]);
    getrandom::fill(entropy.as_mut_slice()).context("failed to collect OS entropy")?;
    Ok(entropy)
}

fn collect_yubikey_entropy(byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!("Collecting {byte_count} bytes of YubiKey entropy");

    loop {
        match try_collect_yubikey_entropy(byte_count) {
            Ok(entropy) => return Ok(entropy),
            Err(error) => {
                info!("Unable to collect YubiKey entropy: {error:#}");
                info!("Connect exactly one compatible smart card and press Enter to retry");

                let mut input = String::new();
                ensure!(
                    io::stdin()
                        .read_line(&mut input)
                        .context("failed to wait for Enter")?
                        != 0,
                    "standard input closed while waiting to retry"
                );
            }
        }
    }
}

fn try_collect_yubikey_entropy(byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    run_gpg_connect_agent(&["SCD SERIALNO", "/bye"]).context("failed to scan for smart cards")?;

    let output = run_gpg_connect_agent(&["SCD GETINFO card_list", "/bye"])
        .context("failed to list smart cards")?;
    let output = str::from_utf8(&output.stdout).context("invalid smart card list from GPG")?;
    let serials = output
        .lines()
        .filter_map(|line| line.strip_prefix("S SERIALNO "))
        .collect::<Vec<_>>();

    ensure!(
        serials.len() == 1,
        "expected exactly one smart card, found {}",
        serials.len()
    );
    let serial = serials[0];
    ensure!(
        !serial.is_empty() && serial.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "GPG returned an invalid smart card serial number"
    );

    let select = format!("SCD SERIALNO --demand={serial} openpgp");
    let random = format!("SCD RANDOM {byte_count}");
    let output = Command::new("gpg-connect-agent")
        .arg("--no-history")
        .arg("/datafile -")
        .arg(select)
        .arg(random)
        .arg("/bye")
        .output()
        .context("failed to start gpg-connect-agent")?;
    let entropy = Zeroizing::new(output.stdout);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("gpg-connect-agent failed with status {}", output.status);
        }
        bail!("gpg-connect-agent failed: {stderr}");
    }

    ensure!(
        entropy.len() == byte_count,
        "GPG returned {} bytes of smart card entropy instead of {byte_count}",
        entropy.len()
    );
    Ok(entropy)
}

fn run_gpg_connect_agent(commands: &[&str]) -> anyhow::Result<std::process::Output> {
    let output = Command::new("gpg-connect-agent")
        .arg("--no-history")
        .args(commands)
        .output()
        .context("failed to start gpg-connect-agent")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("gpg-connect-agent failed with status {}", output.status);
        }
        bail!("gpg-connect-agent failed: {stderr}");
    }

    if let Some(error) = output
        .stdout
        .split(|byte| *byte == b'\n')
        .find(|line| line.starts_with(b"ERR "))
    {
        bail!(
            "GPG card command failed: {}",
            String::from_utf8_lossy(error)
        );
    }

    Ok(output)
}

fn collect_dice_entropy(_byte_count: usize, _sides: u32) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    todo!()
}

fn combine_entropy(
    sources: &[Zeroizing<Vec<u8>>],
    byte_count: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!("Combining entropy from {} sources", sources.len());

    ensure!(!sources.is_empty(), "no entropy sources were provided");

    let mut hasher = Sha3_256::new();
    hasher.update((byte_count as u64).to_be_bytes());

    for (index, source) in sources.iter().enumerate() {
        ensure!(
            source.len() == byte_count,
            "entropy source {index} produced {} bytes instead of {byte_count}",
            source.len()
        );
        hasher.update(source);
    }

    let mut digest = hasher.finalize();
    let combined = Zeroizing::new(digest[..byte_count].to_vec());
    digest.as_mut_slice().zeroize();
    Ok(combined)
}

impl WordCount {
    pub(crate) fn entropy_bytes(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::Eighteen => 24,
            Self::TwentyFour => 32,
        }
    }
}

use anyhow::{Context, ensure};
use log::info;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{Config, WordCount};

pub(crate) fn collect_entropy(config: &Config) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!("Collecting entropy");

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

fn collect_yubikey_entropy(_byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    todo!()
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
    fn entropy_bytes(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::Eighteen => 24,
            Self::TwentyFour => 32,
        }
    }
}

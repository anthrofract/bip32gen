use std::{
    io::{self, IsTerminal, Write as _},
    process::Command,
};

use anyhow::{Context, bail, ensure};
use crypto_bigint::U512;
use log::info;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    cli::{Config, WordCount},
    secret_string::SecretString,
};

pub(crate) fn collect_entropy(config: &Config) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let byte_count = config.words.entropy_bytes();
    let mut sources = Vec::with_capacity(3);

    if config.os_entropy {
        sources.push(collect_os_entropy(byte_count)?);
    }
    if config.openpgp_card_entropy {
        sources.push(collect_openpgp_card_entropy(byte_count)?);
    }
    if let Some(sides) = config.dice_entropy {
        sources.push(collect_dice_entropy(byte_count, sides)?);
    }

    combine_entropy(&sources, byte_count)
}

fn collect_os_entropy(byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!("Collecting {} bits of OS entropy...", byte_count * 8);

    let mut entropy = Zeroizing::new(vec![0; byte_count]);
    getrandom::fill(entropy.as_mut_slice()).context("failed to collect OS entropy")?;
    Ok(entropy)
}

fn collect_openpgp_card_entropy(byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!(
        "Collecting {} bits of OpenPGP smart card entropy...",
        byte_count * 8
    );

    loop {
        match try_collect_openpgp_card_entropy(byte_count) {
            Ok(entropy) => return Ok(entropy),
            Err(error) => {
                info!("Unable to collect OpenPGP smart card entropy: {error:#}");
                info!("Connect exactly one OpenPGP smart card and press Enter to retry");

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

fn try_collect_openpgp_card_entropy(byte_count: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
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

fn collect_dice_entropy(byte_count: usize, sides: u32) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    ensure!(sides >= 2, "a die must have at least two sides");

    let bit_count = byte_count * 8;
    let expected_rolls = expected_dice_rolls(byte_count, sides);
    info!("Collecting {bit_count} bits of dice entropy using d{sides} rolls...");
    info!("Enter dice rolls separated by spaces:");
    info!("Warning: Dice rolls are visible and may remain in terminal scrollback or session logs.");

    let mut value = Zeroizing::new(U512::ZERO);
    let mut range = Zeroizing::new(U512::ONE);
    let mut entered = 0;

    loop {
        let rolls = prompt_for_dice_rolls(entered, expected_rolls, sides)?;

        for roll in rolls.iter().copied() {
            entered += 1;
            if let Some(entropy) = add_dice_roll(&mut value, &mut range, roll, sides, byte_count) {
                info!("{}: Finished.", roll_status(entered, expected_rolls, sides));
                return Ok(entropy);
            }
        }
    }
}

fn prompt_for_dice_rolls(
    entered: usize,
    expected: f64,
    sides: u32,
) -> anyhow::Result<Zeroizing<Vec<u32>>> {
    let mut stderr = io::stderr().lock();
    write!(stderr, "{}: ", roll_status(entered, expected, sides))?;
    stderr.flush()?;

    let stdin = io::stdin();
    let is_terminal = stdin.is_terminal();
    let input = SecretString::read_line().context("failed to read dice rolls")?;
    if !is_terminal {
        writeln!(io::stderr()).context("failed to finish dice prompt")?;
    }

    let mut rolls = Zeroizing::new(Vec::with_capacity(input.split_ascii_whitespace().count()));
    for value in input.split_ascii_whitespace() {
        let Some(roll) = value
            .parse::<u32>()
            .ok()
            .filter(|roll| (1..=sides).contains(roll))
        else {
            info!("Invalid dice input discarded, every roll must be between 1 and {sides}.");
            return Ok(Zeroizing::new(Vec::new()));
        };
        rolls.push(roll);
    }
    Ok(rolls)
}

fn roll_status(entered: usize, expected: f64, sides: u32) -> String {
    format!("[{entered} d{sides} rolls entered of ~{expected:.3}]")
}

fn expected_dice_rolls(byte_count: usize, sides: u32) -> f64 {
    let target = U512::ONE << (byte_count * 8);
    let mask = target - U512::ONE;
    let sides = U512::from(sides);
    let mut residual = U512::ONE;
    let mut survival_probability = 1.0;
    let mut expected_rolls = 0.0;

    while survival_probability > 1e-15 {
        expected_rolls += survival_probability;
        let expanded = residual * sides;
        residual = expanded & mask;
        if residual == U512::ZERO {
            break;
        }
        survival_probability *= u512_to_f64(residual) / u512_to_f64(expanded);
    }

    expected_rolls
}

fn u512_to_f64(value: U512) -> f64 {
    value.to_words().iter().rev().fold(0.0, |result, word| {
        result * 2f64.powi(usize::BITS as i32) + *word as f64
    })
}

fn add_dice_roll(
    value: &mut U512,
    range: &mut U512,
    roll: u32,
    sides: u32,
    byte_count: usize,
) -> Option<Zeroizing<Vec<u8>>> {
    let bit_count = byte_count * 8;
    let sides = U512::from(sides);

    // Append the roll as a base-N digit and track the number of possible sequences.
    *value *= sides;
    *value += U512::from(roll - 1);
    *range *= sides;

    // Only complete groups containing every possible output can be used without bias.
    let limit = (*range >> bit_count) << bit_count;
    if limit == U512::ZERO {
        return None;
    }

    if *value < limit {
        let mut bytes = value.to_be_bytes();
        let entropy = Zeroizing::new(bytes[bytes.len() - byte_count..].to_vec());
        bytes.as_mut_slice().zeroize();
        return Some(entropy);
    }

    // Recycle the leftover range instead of discarding the entropy collected so far.
    *value -= limit;
    *range -= limit;
    None
}

fn combine_entropy(
    sources: &[Zeroizing<Vec<u8>>],
    byte_count: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    info!(
        "Combining entropy from {} sources to produce {} bits of final entropy...",
        sources.len(),
        byte_count * 8
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_expected_dice_rolls() {
        let cases = [
            (16, 6, 50.181_976_529_858_88),
            (24, 6, 75.231_559_236_689_88),
            (32, 6, 100.140_223_540_677_41),
            (16, 20, 30.051_151_539_784_332),
            (24, 20, 45.108_943_717_772_02),
            (32, 20, 60.096_974_045_788_9),
        ];

        for (byte_count, sides, expected) in cases {
            let actual = expected_dice_rolls(byte_count, sides);
            assert!((actual - expected).abs() < 1e-12);
        }
    }

    #[test]
    fn extracts_uniform_entropy_from_dice_rolls() {
        let mut counts = [0; 256];
        let mut rejected = 0;

        for sequence in 0..6_usize.pow(4) {
            let mut sequence = sequence;
            let mut rolls = [0; 4];
            for roll in rolls.iter_mut().rev() {
                *roll = (sequence % 6 + 1) as u32;
                sequence /= 6;
            }

            let mut value = U512::ZERO;
            let mut range = U512::ONE;
            let mut entropy = None;
            for roll in rolls {
                entropy = add_dice_roll(&mut value, &mut range, roll, 6, 1);
            }

            if let Some(entropy) = entropy {
                counts[entropy[0] as usize] += 1;
            } else {
                rejected += 1;
            }
        }

        assert_eq!(rejected, 16);
        assert!(counts.iter().all(|count| *count == 5));
    }
}

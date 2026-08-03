use std::{
    io::{self, IsTerminal, Write as _},
    process::Command,
};

use anyhow::{Context, bail, ensure};
use crypto_bigint::{U512, Word};
use log::{info, warn};
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

    // Pre-flight the card selection without a datafile so any ERR response is
    // visible; in datafile mode gpg-connect-agent swallows ERR lines entirely.
    let select = format!("SCD SERIALNO --demand={serial} openpgp");
    run_gpg_connect_agent(&[select.as_str(), "/bye"])
        .with_context(|| format!("failed to select smart card {serial}"))?;

    // Keep the selection and RANDOM in one invocation so they share a single
    // scdaemon session; a separate invocation would auto-select whatever card
    // is present instead of the serial demanded above.
    let random = format!("SCD RANDOM {byte_count}");
    let mut output = Command::new("gpg-connect-agent")
        .arg("--no-history")
        .arg("/datafile -")
        .arg(select)
        .arg(random)
        .arg("/bye")
        .output()
        .context("failed to start gpg-connect-agent")?;
    let entropy = Zeroizing::new(std::mem::take(&mut output.stdout));

    crate::process::check_command_output("gpg-connect-agent", &output)?;

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

    crate::process::check_command_output("gpg-connect-agent", &output)?;

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
    warn!("Dice rolls are visible and may remain in terminal scrollback or session logs.");

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
        result * 2f64.powi(Word::BITS as i32) + *word as f64
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
            Self::Fifteen => 20,
            Self::Eighteen => 24,
            Self::TwentyOne => 28,
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
            (20, 6, 62.208_379_562_611_8),
            (24, 6, 75.231_559_236_689_88),
            (28, 6, 87.487_062_371_999_37),
            (32, 6, 100.140_223_540_677_41),
            (16, 20, 30.051_151_539_784_332),
            (20, 20, 38.043_400_201_043),
            (24, 20, 45.108_943_717_772_02),
            (28, 20, 52.413_977_244_832_26),
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

    #[test]
    fn combines_entropy_deterministically() {
        // Expected outputs are SHA3-256(be64(byte_count) || sources...) truncated,
        // computed with a reference SHA3-256 implementation (Python hashlib).
        let sources = [
            Zeroizing::new((0..16).collect::<Vec<u8>>()),
            Zeroizing::new((16..32).collect::<Vec<u8>>()),
        ];
        let combined = combine_entropy(&sources, 16).unwrap();
        assert_eq!(
            combined.as_slice(),
            [
                0x7d, 0x01, 0x56, 0xa4, 0xb8, 0x3e, 0x45, 0x4b, 0xe7, 0x5d, 0x7b, 0x8f, 0x07, 0xfc,
                0xc7, 0x61,
            ]
        );

        let sources = [Zeroizing::new((0..32).collect::<Vec<u8>>())];
        let combined = combine_entropy(&sources, 32).unwrap();
        assert_eq!(
            combined.as_slice(),
            [
                0x3c, 0xbd, 0xc8, 0x06, 0x02, 0x02, 0xd4, 0x8d, 0xcb, 0x8f, 0x75, 0xab, 0x0b, 0x85,
                0xa2, 0x68, 0x55, 0x4e, 0x5c, 0x7c, 0x60, 0xc7, 0x13, 0x7e, 0x51, 0xa4, 0x4c, 0x5f,
                0x2f, 0xac, 0x2b, 0xde,
            ]
        );
    }

    #[test]
    fn rejects_invalid_entropy_sources() {
        assert!(combine_entropy(&[], 16).is_err());
        assert!(combine_entropy(&[Zeroizing::new(vec![0; 15])], 16).is_err());
        assert!(combine_entropy(&[Zeroizing::new(vec![0; 17])], 16).is_err());
    }
}

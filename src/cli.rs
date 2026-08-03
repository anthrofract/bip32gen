use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, ensure};
use clap::{ArgAction, CommandFactory, Parser, ValueEnum, error::ErrorKind};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Generate a BIP-39 mnemonic from multiple entropy sources"
)]
struct Cli {
    /// Use entropy from the operating system's cryptographic random number generator
    #[arg(long = "os", default_value_t = true, action = ArgAction::Set)]
    os_entropy: bool,

    /// Use entropy from interactive dice rolls
    #[arg(long = "dice", default_value_t = true, action = ArgAction::Set)]
    dice_entropy: bool,

    /// Number of sides on each die (defaults to 6)
    #[arg(long, value_parser = clap::value_parser!(u32).range(2..))]
    dice_sides: Option<u32>,

    /// Use entropy from an OpenPGP smart card such as a YubiKey
    #[arg(long = "openpgp-card", default_value_t = true, action = ArgAction::Set)]
    openpgp_card_entropy: bool,

    /// Number of words in the generated mnemonic
    #[arg(long, default_value = "12")]
    words: WordCount,

    /// OpenPGP public key used to encrypt the mnemonic with GPG
    #[arg(long, value_name = "PATH")]
    pgp_pubkey: Option<PathBuf>,

    /// Output path (defaults to seed.txt or seed.txt.asc when encrypted)
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Overwrite an existing output file
    #[arg(short, long)]
    force: bool,
}

#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) os_entropy: bool,
    pub(crate) openpgp_card_entropy: bool,
    pub(crate) dice_entropy: Option<u32>,
    pub(crate) words: WordCount,
    pub(crate) pgp_pubkey: Option<PathBuf>,
    pub(crate) output_path: PathBuf,
    pub(crate) overwrite: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum WordCount {
    #[value(name = "12")]
    Twelve,
    #[value(name = "15")]
    Fifteen,
    #[value(name = "18")]
    Eighteen,
    #[value(name = "21")]
    TwentyOne,
    #[value(name = "24")]
    TwentyFour,
}

impl TryFrom<Cli> for Config {
    type Error = anyhow::Error;

    fn try_from(cli: Cli) -> Result<Self, Self::Error> {
        // Validate entropy source selection before resolving source-specific options.
        ensure!(
            cli.dice_entropy || cli.dice_sides.is_none(),
            "--dice-sides cannot be used when --dice is false"
        );
        ensure!(
            cli.os_entropy || cli.dice_entropy || cli.openpgp_card_entropy,
            "at least one entropy source must be enabled"
        );

        // Check optional runtime dependencies before collecting any entropy.
        if cli.openpgp_card_entropy {
            crate::process::validate_command("gpg-connect-agent")?;
        }
        if cli.pgp_pubkey.is_some() {
            crate::process::validate_command("gpg")?;
        }

        let output_path = cli.output.unwrap_or_else(|| {
            PathBuf::from(if cli.pgp_pubkey.is_some() {
                "seed.txt.asc"
            } else {
                "seed.txt"
            })
        });

        // Fail early if encryption was requested with an unusable public key.
        if let Some(pgp_pubkey) = &cli.pgp_pubkey {
            ensure!(
                pgp_pubkey.is_file(),
                "OpenPGP public key '{}' is not a file",
                pgp_pubkey.display()
            );
            let pgp_pubkey = File::open(pgp_pubkey).with_context(|| {
                format!("cannot read OpenPGP public key '{}'", pgp_pubkey.display())
            })?;

            if let Ok(output_metadata) = fs::metadata(&output_path) {
                let key_metadata = pgp_pubkey.metadata()?;
                ensure!(
                    key_metadata.dev() != output_metadata.dev()
                        || key_metadata.ino() != output_metadata.ino(),
                    "OpenPGP public key and output must be different files"
                );
            }
        }

        // Validate the destination without creating or truncating the output file.
        let output_dir = output_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        ensure!(
            output_dir.is_dir(),
            "output directory '{}' does not exist",
            output_dir.display()
        );
        fs::read_dir(output_dir).with_context(|| {
            format!("cannot access output directory '{}'", output_dir.display())
        })?;

        if output_path.try_exists()? {
            ensure!(
                output_path.is_file(),
                "output path '{}' is not a file",
                output_path.display()
            );
            ensure!(
                cli.force,
                "output file '{}' already exists; use --force to overwrite it",
                output_path.display()
            );
            OpenOptions::new()
                .write(true)
                .open(&output_path)
                .with_context(|| format!("cannot write output file '{}'", output_path.display()))?;
        }

        Ok(Self {
            os_entropy: cli.os_entropy,
            dice_entropy: cli.dice_entropy.then(|| cli.dice_sides.unwrap_or(6)),
            openpgp_card_entropy: cli.openpgp_card_entropy,
            words: cli.words,
            pgp_pubkey: cli.pgp_pubkey,
            output_path,
            overwrite: cli.force,
        })
    }
}

pub(crate) fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buffer, record| match record.level() {
            log::Level::Error => writeln!(buffer, "ERROR: {}", record.args()),
            log::Level::Warn => {
                let style = buffer.default_level_style(log::Level::Error);
                writeln!(buffer, "🚨 {style}WARNING{style:#}: {}", record.args())
            }
            _ => writeln!(buffer, "{}", record.args()),
        })
        .init();
}

pub(crate) fn parse() -> Config {
    let config = Config::try_from(Cli::parse()).unwrap_or_else(|error| {
        Cli::command()
            .error(ErrorKind::ValueValidation, error.to_string())
            .exit()
    });
    log::debug!("{config:#?}");
    config
}

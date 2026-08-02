use std::{
    fs::{self, File, OpenOptions},
    io::Write,
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

    /// Use entropy from a YubiKey
    #[arg(long = "yubikey", default_value_t = true, action = ArgAction::Set)]
    yubikey_entropy: bool,

    /// Number of words in the generated mnemonic
    #[arg(long, default_value = "12")]
    words: WordCount,

    /// OpenPGP public key used to encrypt the mnemonic with GPG
    #[arg(long, value_name = "PATH")]
    gpg_pubkey: Option<PathBuf>,

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
    pub(crate) dice_entropy: Option<u32>,
    pub(crate) yubikey_entropy: bool,
    pub(crate) words: WordCount,
    pub(crate) gpg_pubkey: Option<PathBuf>,
    pub(crate) output_path: PathBuf,
    pub(crate) overwrite: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum WordCount {
    #[value(name = "12")]
    Twelve,
    #[value(name = "18")]
    Eighteen,
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
            cli.os_entropy || cli.dice_entropy || cli.yubikey_entropy,
            "at least one entropy source must be enabled"
        );

        let output_path = cli.output.unwrap_or_else(|| {
            PathBuf::from(if cli.gpg_pubkey.is_some() {
                "seed.txt.asc"
            } else {
                "seed.txt"
            })
        });

        // Fail early if encryption was requested with an unusable public key.
        if let Some(gpg_pubkey) = &cli.gpg_pubkey {
            ensure!(
                gpg_pubkey.is_file(),
                "GPG public key '{}' is not a file",
                gpg_pubkey.display()
            );
            File::open(gpg_pubkey).with_context(|| {
                format!("cannot read GPG public key '{}'", gpg_pubkey.display())
            })?;
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
            yubikey_entropy: cli.yubikey_entropy,
            words: cli.words,
            gpg_pubkey: cli.gpg_pubkey,
            output_path,
            overwrite: cli.force,
        })
    }
}

pub(crate) fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buffer, record| writeln!(buffer, "{}", record.args()))
        .init();
}

pub(crate) fn parse() -> Config {
    Config::try_from(Cli::parse()).unwrap_or_else(|error| {
        Cli::command()
            .error(ErrorKind::ValueValidation, error.to_string())
            .exit()
    })
}

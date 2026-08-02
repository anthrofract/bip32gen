use std::path::PathBuf;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum WordCount {
    #[value(name = "12")]
    Twelve,
    #[value(name = "18")]
    Eighteen,
    #[value(name = "24")]
    TwentyFour,
}

impl Cli {
    fn validate(&self) -> Result<(), clap::Error> {
        if !self.dice_entropy && self.dice_sides.is_some() {
            return Err(Cli::command().error(
                ErrorKind::ArgumentConflict,
                "--dice-sides cannot be used when --dice is false",
            ));
        }

        if !self.os_entropy && !self.dice_entropy && !self.yubikey_entropy {
            return Err(Cli::command().error(
                ErrorKind::MissingRequiredArgument,
                "at least one entropy source must be enabled",
            ));
        }

        Ok(())
    }
}

fn main() {
    let cli = Cli::parse();

    if let Err(error) = cli.validate() {
        error.exit();
    }
}

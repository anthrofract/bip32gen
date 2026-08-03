#[cfg(not(unix))]
compile_error!("bip39gen only supports unix-like operating systems");

mod cli;
mod entropy;
mod process;
mod run;
mod secret_string;

fn main() -> anyhow::Result<()> {
    cli::init_logging();
    let config = cli::parse();
    run::run(config)
}

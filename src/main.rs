mod cli;
mod entropy;
mod run;
mod secret_string;

fn main() -> anyhow::Result<()> {
    cli::init_logging();
    let config = cli::parse();
    run::run(config)
}

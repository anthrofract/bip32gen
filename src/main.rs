mod cli;
mod entropy;
mod run;

fn main() -> anyhow::Result<()> {
    cli::init_logging();
    let config = cli::parse();
    run::run(config)
}

use std::fs;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // path to attestation doc hex string file
    #[arg(long)]
    attestation: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let attestation = fs::read_to_string(&cli.attestation).context(format!(
        "Failed to read attestation hex string from {}",
        cli.attestation
    ))?;
    let attestation =
        hex::decode(attestation).context("Failed to decode attestation hex string")?;
    let parsed_attestation = oyster::decode_attestation(attestation.clone())
        .context("Failed to decode the attestation doc")?;

    oyster::verify_with_timestamp(
        attestation,
        parsed_attestation.pcrs,
        parsed_attestation.timestamp,
    )
    .context("Failed to verify the attestation doc")?;
    println!("{:?}", parsed_attestation);

    Ok(())
}

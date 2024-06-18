use std::fs;

use anyhow::{Context, Result};
use clap::Parser;
use verifier::handler::{verify, UserError};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // path to secp256k1 private key file (e.g. /app/secp256k1.sec)
    #[arg(long)]
    secp256k1_secret: String,

    // path to secp256k1 public key file (e.g. /app/secp256k1.pub)
    #[arg(long)]
    secp256k1_public: String,

    // path to attestation hex string file
    #[arg(long)]
    attestation: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let secp256k1_secret = fs::read(&cli.secp256k1_secret).context(format!(
        "Failed to read secp256k1_secret from {}",
        cli.secp256k1_secret
    ))?;
    let secp256k1_secret = secp256k1::SecretKey::from_slice(&secp256k1_secret)
        .context("Unable to decode secp256k1_secret key from slice")?;

    let secp256k1_public = fs::read(&cli.secp256k1_public).context(format!(
        "Failed to read secp256k1_public from {}",
        cli.secp256k1_public
    ))?;
    let secp256k1_public: [u8; 64] = secp256k1_public
        .as_slice()
        .try_into()
        .context("Invalid public key length")?;

    let attestation = fs::read(&cli.attestation).context(format!(
        "Failed to read attestation data from {}",
        cli.attestation
    ))?;

    let attestation = hex::decode(attestation).map_err(UserError::AttestationDecode)?;

    let verification_response = verify(attestation, &secp256k1_secret, &secp256k1_public)?;
    println!("{:?}", verification_response);

    Ok(())
}

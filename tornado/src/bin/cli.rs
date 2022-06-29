//! ZKP Generator

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use tornado::{config::types::Key, crypto::rand::Rand};

#[derive(Parser)]
pub struct Args {
	#[clap(subcommand)]
	pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
	Mint,
	Claim { key: String },
}

fn main() -> Result<()> {
	let mut rng = OsRng;
	let args = Args::try_parse()?;
	match args.command {
		Command::Mint => {
			let key = rng.gen::<_, Key>();
			// TODO: let post = to_private(proving_key, parameters, key, value, &mut rng)?;
			// println!("UTXO: {:?}", post.utxo);
			// println!("ZKP: {:?}", post.proof);
			println!("Key: {}", hex::encode(key));
		},
		Command::Claim { key } => match Key::try_from(hex::decode(key)?) {
			Ok(key) => {
				println!("Root: ");
				println!("ZKP: ");
			},
			_ => bail!("Unable to parse claim key."),
		},
	}
	Ok(())
}

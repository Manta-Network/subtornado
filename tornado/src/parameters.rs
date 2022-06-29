//! Parameters

use crate::{
	circuit::{claim_keys, mint_keys},
	config::{Config, Parameters, ProvingKey, VerifyingKey},
	crypto::rand::{Rand, SeedableRng},
};
use rand_chacha::ChaCha20Rng;

pub fn generate() -> (Parameters, (ProvingKey, VerifyingKey), (ProvingKey, VerifyingKey)) {
	let mut rng = ChaCha20Rng::from_seed([8; 32]);
	let parameters: Parameters = rng.gen();
	let mint_keys = mint_keys::<Config, _>(&parameters, &mut rng).unwrap();
	let claim_keys = claim_keys::<Config, _>(&parameters, &mut rng).unwrap();
	(parameters, mint_keys, claim_keys)
}

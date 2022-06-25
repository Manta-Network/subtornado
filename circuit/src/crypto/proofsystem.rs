//! Proof Systems

use rand_core::{CryptoRng, RngCore};

///
pub trait ProofSystem {
	///
	type Compiler;

	///
	type ProvingKey;

	///
	type VerifyingKey;

	///
	type Proof;

	///
	type Input;

	///
	type Error;

	///
	fn for_compile() -> Self::Compiler;

	///
	fn for_prove() -> Self::Compiler;

	///
	fn compile<R>(
		compiler: Self::Compiler,
		rng: &mut R,
	) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error>
	where
		R: CryptoRng + RngCore + ?Sized;

	///
	fn prove<R>(
		proving_key: &Self::ProvingKey,
		compiler: Self::Compiler,
		rng: &mut R,
	) -> Result<Self::Proof, Self::Error>
	where
		R: CryptoRng + RngCore + ?Sized;

	///
	fn verify(
		verifying_key: &Self::VerifyingKey,
		input: &[Self::Input],
		proof: Self::Proof,
	) -> bool;
}

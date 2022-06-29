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
		proof: &Self::Proof,
	) -> Result<bool, Self::Error>;
}

/// Arkworks Backend
pub mod arkworks {
	use super::*;
	use crate::crypto::arkworks::R1CS;
	use ark_ec::PairingEngine;
	use ark_groth16::{Groth16 as ArkGroth16, Proof, ProvingKey, VerifyingKey};
	use ark_snark::SNARK;
	use core::marker::PhantomData;

	/// Arkworks Groth16 Proof System
	pub struct Groth16<E>(PhantomData<E>)
	where
		E: PairingEngine;

	impl<E> ProofSystem for Groth16<E>
	where
		E: PairingEngine,
	{
		type Compiler = R1CS<E::Fr>;
		type ProvingKey = ProvingKey<E>;
		type VerifyingKey = VerifyingKey<E>;
		type Input = E::Fr;
		type Proof = Proof<E>;
		type Error = ();

		#[inline]
		fn for_compile() -> Self::Compiler {
			Self::Compiler::for_compile()
		}

		#[inline]
		fn for_prove() -> Self::Compiler {
			Self::Compiler::for_prove()
		}

		#[inline]
		fn compile<R>(
			compiler: Self::Compiler,
			mut rng: &mut R,
		) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error>
		where
			R: CryptoRng + RngCore + ?Sized,
		{
			let (proving_key, verifying_key) =
				ArkGroth16::circuit_specific_setup(compiler, &mut rng).map_err(|_| ())?;
			Ok((proving_key, verifying_key))
		}

		#[inline]
		fn prove<R>(
			proving_key: &Self::ProvingKey,
			compiler: Self::Compiler,
			mut rng: &mut R,
		) -> Result<Self::Proof, Self::Error>
		where
			R: CryptoRng + RngCore + ?Sized,
		{
			ArkGroth16::prove(proving_key, compiler, &mut rng).map_err(|_| ())
		}

		#[inline]
		fn verify(
			verifying_key: &Self::VerifyingKey,
			input: &[Self::Input],
			proof: &Self::Proof,
		) -> Result<bool, Self::Error> {
			ArkGroth16::verify(verifying_key, input, proof).map_err(|_| ())
		}
	}
}

//! Subtornado Circuits

use crate::crypto::{
	accumulator::Accumulator,
	eclair::alloc::{
		mode::{Derived, Public, Secret},
		Allocate, Allocator, Constant, Variable,
	},
	proofsystem::ProofSystem,
};
use rand_core::{CryptoRng, RngCore};

///
pub trait Parameters<COM = ()> {
	///
	type Field;

	///
	type MembershipProof;

	///
	fn assert_eq(&self, lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM);

	///
	fn utxo(&self, key: &Self::Field, value: &Self::Field, compiler: &mut COM) -> Self::Field;

	///
	fn void_number(&self, key: &Self::Field, utxo: &Self::Field, compiler: &mut COM)
		-> Self::Field;

	///
	fn assert_membership(
		&self,
		utxo: &Self::Field,
		root: &Self::Field,
		membership_proof: &Self::MembershipProof,
		compiler: &mut COM,
	);
}

///
pub trait Configuration {
	type Compiler;
	type ProvingKey;
	type VerifyingKey;
	type Proof;
	type Error;
	type ProofSystem: ProofSystem<
		Compiler = Self::Compiler,
		ProvingKey = Self::ProvingKey,
		VerifyingKey = Self::VerifyingKey,
		Proof = Self::Proof,
		Error = Self::Error,
	>;
	type Field;
	type MembershipProof;
	type Parameters: Parameters<Field = Self::Field, MembershipProof = Self::MembershipProof>;
	type Accumulator: Accumulator<
		Self::Field,
		Root = Self::Field,
		MembershipProof = Self::MembershipProof,
	>;
	type FieldVar: Variable<Public, Self::Compiler, Type = Self::Field>
		+ Variable<Secret, Self::Compiler, Type = Self::Field>;
	type MembershipProofVar: Variable<Secret, Self::Compiler, Type = Self::MembershipProof>;
	type ParametersVar: Parameters<
			Self::Compiler,
			Field = Self::FieldVar,
			MembershipProof = Self::MembershipProofVar,
		> + Constant<Self::Compiler, Type = Self::Parameters>;
}

///
pub struct Mint<C>
where
	C: Configuration,
{
	pub key: C::Field,
	pub value: C::Field,
	pub utxo: C::Field,
}

impl<C> Mint<C>
where
	C: Configuration,
{
	///
	#[inline]
	pub fn new(parameters: &C::Parameters, key: C::Field, value: C::Field) -> Self {
		Self { utxo: parameters.utxo(&key, &value, &mut ()), key, value }
	}
}

///
pub struct MintVar<C>
where
	C: Configuration,
{
	pub key: C::FieldVar,
	pub value: C::FieldVar,
	pub utxo: C::FieldVar,
}

impl<C> MintVar<C>
where
	C: Configuration,
{
	///
	#[inline]
	pub fn assert_valid(&self, parameters: &C::ParametersVar, compiler: &mut C::Compiler) {
		parameters.assert_eq(
			&self.utxo,
			&parameters.utxo(&self.key, &self.value, compiler),
			compiler,
		)
	}
}

impl<C> Variable<Derived, C::Compiler> for MintVar<C>
where
	C: Configuration,
{
	type Type = Mint<C>;

	#[inline]
	fn new_unknown(compiler: &mut C::Compiler) -> Self {
		Self {
			key: compiler.allocate_unknown::<Secret, _>(),
			value: compiler.allocate_unknown::<Secret, _>(),
			utxo: compiler.allocate_unknown::<Public, _>(),
		}
	}

	#[inline]
	fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
		Self {
			key: this.key.as_known::<Secret, _>(compiler),
			value: this.value.as_known::<Secret, _>(compiler),
			utxo: this.utxo.as_known::<Public, _>(compiler),
		}
	}
}

///
pub struct MintPost<C>
where
	C: Configuration,
{
	pub utxo: C::Field,
	pub proof: C::Proof,
}

///
#[inline]
pub fn mint_keys<C, R>(
	parameters: &C::Parameters,
	rng: &mut R,
) -> Result<(C::ProvingKey, C::VerifyingKey), C::Error>
where
	C: Configuration,
	R: CryptoRng + RngCore + ?Sized,
{
	let mut compiler = C::ProofSystem::for_compile();
	MintVar::<C>::assert_valid(
		&compiler.allocate_unknown(),
		&parameters.as_constant(&mut compiler),
		&mut compiler,
	);
	C::ProofSystem::compile(compiler, rng)
}

///
#[inline]
pub fn mint<C, R>(
	proving_key: &C::ProvingKey,
	parameters: &C::Parameters,
	key: C::Field,
	value: C::Field,
	rng: &mut R,
) -> Result<MintPost<C>, C::Error>
where
	C: Configuration,
	R: CryptoRng + RngCore + ?Sized,
{
	let data = Mint::new(parameters, key, value);
	let mut compiler = C::ProofSystem::for_prove();
	MintVar::<C>::assert_valid(
		&data.as_known(&mut compiler),
		&parameters.as_constant(&mut compiler),
		&mut compiler,
	);
	Ok(MintPost { utxo: data.utxo, proof: C::ProofSystem::prove(proving_key, compiler, rng)? })
}

///
pub struct Claim<C>
where
	C: Configuration,
{
	pub key: C::Field,
	pub value: C::Field,
	pub root: C::Field,
	pub membership_proof: C::MembershipProof,
	pub void_number: C::Field,
}

impl<C> Claim<C>
where
	C: Configuration,
{
	///
	#[inline]
	pub fn new(
		parameters: &C::Parameters,
		accumulator: &C::Accumulator,
		key: C::Field,
		value: C::Field,
	) -> Option<Self> {
		let utxo = parameters.utxo(&key, &value, &mut ());
		let (root, membership_proof) = accumulator.membership_proof(&utxo)?;
		Some(Self {
			void_number: parameters.void_number(&key, &utxo, &mut ()),
			key,
			value,
			root,
			membership_proof,
		})
	}
}

///
pub struct ClaimVar<C>
where
	C: Configuration,
{
	pub key: C::FieldVar,
	pub value: C::FieldVar,
	pub root: C::FieldVar,
	pub membership_proof: C::MembershipProofVar,
	pub void_number: C::FieldVar,
}

impl<C> ClaimVar<C>
where
	C: Configuration,
{
	///
	#[inline]
	pub fn assert_valid(&self, parameters: &C::ParametersVar, compiler: &mut C::Compiler) {
		let utxo = parameters.utxo(&self.key, &self.value, compiler);
		parameters.assert_membership(&utxo, &self.root, &self.membership_proof, compiler);
		parameters.assert_eq(
			&self.void_number,
			&parameters.void_number(&self.key, &utxo, compiler),
			compiler,
		);
	}
}

impl<C> Variable<Derived, C::Compiler> for ClaimVar<C>
where
	C: Configuration,
{
	type Type = Claim<C>;

	#[inline]
	fn new_unknown(compiler: &mut C::Compiler) -> Self {
		Self {
			key: compiler.allocate_unknown::<Secret, _>(),
			value: compiler.allocate_unknown::<Secret, _>(),
			root: compiler.allocate_unknown::<Public, _>(),
			membership_proof: compiler.allocate_unknown::<Secret, _>(),
			void_number: compiler.allocate_unknown::<Public, _>(),
		}
	}

	#[inline]
	fn new_known(this: &Self::Type, compiler: &mut C::Compiler) -> Self {
		Self {
			key: this.key.as_known::<Secret, _>(compiler),
			value: this.value.as_known::<Secret, _>(compiler),
			root: this.root.as_known::<Public, _>(compiler),
			membership_proof: this.membership_proof.as_known::<Secret, _>(compiler),
			void_number: this.void_number.as_known::<Public, _>(compiler),
		}
	}
}

///
pub struct ClaimPost<C>
where
	C: Configuration,
{
	pub root: C::Field,
	pub void_number: C::Field,
	pub proof: C::Proof,
}

///
#[inline]
pub fn claim_keys<C, R>(
	parameters: &C::Parameters,
	rng: &mut R,
) -> Result<(C::ProvingKey, C::VerifyingKey), C::Error>
where
	C: Configuration,
	R: CryptoRng + RngCore + ?Sized,
{
	let mut compiler = C::ProofSystem::for_compile();
	ClaimVar::<C>::assert_valid(
		&compiler.allocate_unknown(),
		&parameters.as_constant(&mut compiler),
		&mut compiler,
	);
	C::ProofSystem::compile(compiler, rng)
}

///
#[inline]
pub fn claim<C, R>(
	proving_key: &C::ProvingKey,
	parameters: &C::Parameters,
	accumulator: &C::Accumulator,
	key: C::Field,
	value: C::Field,
	rng: &mut R,
) -> Result<ClaimPost<C>, C::Error>
where
	C: Configuration,
	R: CryptoRng + RngCore + ?Sized,
{
	let data = Claim::new(parameters, accumulator, key, value).expect("FIXME");
	let mut compiler = C::ProofSystem::for_prove();
	ClaimVar::<C>::assert_valid(
		&data.as_known(&mut compiler),
		&parameters.as_constant(&mut compiler),
		&mut compiler,
	);
	Ok(ClaimPost {
		root: data.root,
		void_number: data.void_number,
		proof: C::ProofSystem::prove(proving_key, compiler, rng)?,
	})
}

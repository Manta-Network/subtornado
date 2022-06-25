//! Subtornado Circuits

extern crate alloc;

// TODO: pub mod merkle;
// TODO: pub mod poseidon;
pub mod crypto;

use crate::crypto::{
	alloc::{
		mode::{Derived, Public, Secret},
		Allocate, Allocator, Constant, Variable,
	},
	proofsystem::ProofSystem,
};
use rand_core::{CryptoRng, RngCore};

///
pub trait Accumulator<T> {
	///
	type Root;

	///
	type MembershipProof;

	///
	fn insert(&mut self, item: T);

	///
	fn membership_proof(&self, item: &T) -> Option<(Self::Root, Self::MembershipProof)>;
}

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
	///
	type Compiler;

	///
	type ProvingKey;

	///
	type VerifyingKey;

	///
	type Proof;

	///
	type Error;

	///
	type ProofSystem: ProofSystem<
		Compiler = Self::Compiler,
		ProvingKey = Self::ProvingKey,
		VerifyingKey = Self::VerifyingKey,
		Proof = Self::Proof,
		Error = Self::Error,
	>;

	///
	type Field;

	///
	type MembershipProof;

	///
	type Parameters: Parameters<Field = Self::Field, MembershipProof = Self::MembershipProof>;

	///
	type Accumulator: Accumulator<
		Self::Field,
		Root = Self::Field,
		MembershipProof = Self::MembershipProof,
	>;

	///
	type FieldVar: Variable<Public, Self::Compiler, Type = Self::Field>
		+ Variable<Secret, Self::Compiler, Type = Self::Field>;

	///
	type MembershipProofVar: Variable<Secret, Self::Compiler, Type = Self::MembershipProof>;

	///
	type ParametersVar: Parameters<
			Self::Compiler,
			Field = Self::FieldVar,
			MembershipProof = Self::MembershipProofVar,
		> + Constant<Self::Compiler, Type = Self::Parameters>;
}

///
pub struct ToPrivate<C>
where
	C: Configuration,
{
	///
	pub key: C::Field,

	///
	pub value: C::Field,

	///
	pub utxo: C::Field,
}

impl<C> ToPrivate<C>
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
pub struct ToPrivateVar<C>
where
	C: Configuration,
{
	///
	pub key: C::FieldVar,

	///
	pub value: C::FieldVar,

	///
	pub utxo: C::FieldVar,
}

impl<C> ToPrivateVar<C>
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

impl<C> Variable<Derived, C::Compiler> for ToPrivateVar<C>
where
	C: Configuration,
{
	type Type = ToPrivate<C>;

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
pub struct ToPrivatePost<C>
where
	C: Configuration,
{
	///
	pub utxo: C::Field,

	///
	pub proof: C::Proof,
}

///
#[inline]
pub fn to_private<C, R>(
	proving_key: &C::ProvingKey,
	parameters: &C::Parameters,
	key: C::Field,
	value: C::Field,
	rng: &mut R,
) -> Result<ToPrivatePost<C>, C::Error>
where
	C: Configuration,
	R: CryptoRng + RngCore + ?Sized,
{
	let data = ToPrivate::new(parameters, key, value);
	let mut compiler = C::ProofSystem::for_prove();
	ToPrivateVar::<C>::assert_valid(
		&data.as_known(&mut compiler),
		&parameters.as_constant(&mut compiler),
		&mut compiler,
	);
	Ok(ToPrivatePost { utxo: data.utxo, proof: C::ProofSystem::prove(proving_key, compiler, rng)? })
}

///
pub struct ToPublic<C>
where
	C: Configuration,
{
	///
	pub key: C::Field,

	///
	pub value: C::Field,

	///
	pub root: C::Field,

	///
	pub membership_proof: C::MembershipProof,

	///
	pub void_number: C::Field,
}

impl<C> ToPublic<C>
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
pub struct ToPublicVar<C>
where
	C: Configuration,
{
	///
	pub key: C::FieldVar,

	///
	pub value: C::FieldVar,

	///
	pub root: C::FieldVar,

	///
	pub membership_proof: C::MembershipProofVar,

	///
	pub void_number: C::FieldVar,
}

impl<C> ToPublicVar<C>
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

impl<C> Variable<Derived, C::Compiler> for ToPublicVar<C>
where
	C: Configuration,
{
	type Type = ToPublic<C>;

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
pub struct ToPublicPost<C>
where
	C: Configuration,
{
	///
	pub root: C::Field,

	///
	pub void_number: C::Field,

	///
	pub proof: C::Proof,
}

///
#[inline]
pub fn to_public<C, R>(
	proving_key: &C::ProvingKey,
	parameters: &C::Parameters,
	accumulator: &C::Accumulator,
	key: C::Field,
	value: C::Field,
	rng: &mut R,
) -> Result<ToPublicPost<C>, C::Error>
where
	C: Configuration,
	R: CryptoRng + RngCore + ?Sized,
{
	let data = ToPublic::new(parameters, accumulator, key, value).expect("FIXME");
	let mut compiler = C::ProofSystem::for_prove();
	ToPublicVar::<C>::assert_valid(
		&data.as_known(&mut compiler),
		&parameters.as_constant(&mut compiler),
		&mut compiler,
	);
	Ok(ToPublicPost {
		root: data.root,
		void_number: data.void_number,
		proof: C::ProofSystem::prove(proving_key, compiler, rng)?,
	})
}

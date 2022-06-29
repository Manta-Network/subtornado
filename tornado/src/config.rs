//! Subtornado Configuration

use crate::{
	circuit::{self, Configuration},
	crypto::{
		accumulator,
		arkworks::{Fp, FpVar, R1CS},
		eclair::{
			alloc::{Allocate, Constant},
			bool::{Assert, AssertEq},
		},
		merkle_tree::{
			self,
			path::{constraint::PathVar, Path},
			test::HashParameterSampling,
		},
		poseidon,
		proofsystem::{self, arkworks::Groth16},
		rand::{Rand, RngCore, Sample},
	},
};

pub const MERKLE_TREE_HEIGHT: usize = 20;

pub type Pairing = ark_bls12_381::Bls12_381;
pub type ConstraintField = ark_bls12_381::Fr;
pub type Scalar = Fp<ConstraintField>;
pub type ScalarVar = FpVar<ConstraintField>;
pub type Compiler = R1CS<ConstraintField>;

pub struct PoseidonSpec<const ARITY: usize>;

impl poseidon::arkworks::Specification for PoseidonSpec<2> {
	type Field = ConstraintField;
	const FULL_ROUNDS: usize = 8;
	const PARTIAL_ROUNDS: usize = 55;
	const SBOX_EXPONENT: u64 = 5;
}

pub type Poseidon2 = poseidon::Hasher<PoseidonSpec<2>, 2>;
pub type Poseidon2Var = poseidon::Hasher<PoseidonSpec<2>, 2, Compiler>;

pub struct MerkleTreeInnerHash;

impl merkle_tree::InnerHash for MerkleTreeInnerHash {
	type LeafDigest = Scalar;
	type Parameters = Poseidon2;
	type Output = Scalar;

	#[inline]
	fn join(
		parameters: &Self::Parameters,
		lhs: &Self::Output,
		rhs: &Self::Output,
		compiler: &mut (),
	) -> Self::Output {
		parameters.hash([lhs, rhs], compiler)
	}

	#[inline]
	fn join_leaves(
		parameters: &Self::Parameters,
		lhs: &Self::LeafDigest,
		rhs: &Self::LeafDigest,
		compiler: &mut (),
	) -> Self::Output {
		parameters.hash([lhs, rhs], compiler)
	}
}

pub struct MerkleTreeInnerHashVar;

impl merkle_tree::InnerHash<Compiler> for MerkleTreeInnerHashVar {
	type LeafDigest = ScalarVar;
	type Parameters = Poseidon2Var;
	type Output = ScalarVar;

	#[inline]
	fn join(
		parameters: &Self::Parameters,
		lhs: &Self::Output,
		rhs: &Self::Output,
		compiler: &mut Compiler,
	) -> Self::Output {
		parameters.hash([lhs, rhs], compiler)
	}

	#[inline]
	fn join_leaves(
		parameters: &Self::Parameters,
		lhs: &Self::LeafDigest,
		rhs: &Self::LeafDigest,
		compiler: &mut Compiler,
	) -> Self::Output {
		parameters.hash([lhs, rhs], compiler)
	}
}

pub struct MerkleTreeConfiguration;

impl merkle_tree::HashConfiguration for MerkleTreeConfiguration {
	type LeafHash = merkle_tree::IdentityLeafHash<Scalar>;
	type InnerHash = MerkleTreeInnerHash;
}

impl merkle_tree::HashConfiguration<Compiler> for MerkleTreeConfiguration {
	type LeafHash = merkle_tree::IdentityLeafHash<ScalarVar, Compiler>;
	type InnerHash = MerkleTreeInnerHashVar;
}

impl merkle_tree::Configuration for MerkleTreeConfiguration {
	const HEIGHT: usize = MERKLE_TREE_HEIGHT;
}

impl merkle_tree::Configuration<Compiler> for MerkleTreeConfiguration {
	const HEIGHT: usize = MERKLE_TREE_HEIGHT;
}

impl Constant<Compiler> for MerkleTreeConfiguration {
	type Type = MerkleTreeConfiguration;

	#[inline]
	fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
		let _ = (this, compiler);
		Self
	}
}

impl HashParameterSampling for MerkleTreeConfiguration {
	type LeafHashParameterDistribution = ();
	type InnerHashParameterDistribution = ();

	#[inline]
	fn sample_leaf_hash_parameters<R>(
		distribution: Self::LeafHashParameterDistribution,
		rng: &mut R,
	) -> merkle_tree::LeafHashParameters<Self>
	where
		R: RngCore + ?Sized,
	{
		let _ = (distribution, rng);
	}

	#[inline]
	fn sample_inner_hash_parameters<R>(
		distribution: Self::InnerHashParameterDistribution,
		rng: &mut R,
	) -> merkle_tree::InnerHashParameters<Self>
	where
		R: RngCore + ?Sized,
	{
		rng.sample(distribution)
	}
}

pub struct Parameters {
	pub utxo_hash: Poseidon2,
	pub void_number_hash: Poseidon2,
	pub merkle_tree_parameters: merkle_tree::Parameters<MerkleTreeConfiguration>,
}

impl Sample for Parameters {
	fn sample<R>(_: (), rng: &mut R) -> Self
	where
		R: RngCore + ?Sized,
	{
		Self {
			utxo_hash: rng.gen(),
			void_number_hash: rng.gen(),
			merkle_tree_parameters: rng.gen(),
		}
	}
}

impl circuit::Parameters for Parameters {
	type Field = Scalar;
	type MembershipProof = Path<MerkleTreeConfiguration>;

	#[inline]
	fn assert_eq(&self, lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) {
		assert_eq!(lhs, rhs)
	}

	#[inline]
	fn utxo(&self, key: &Self::Field, value: &Self::Field, compiler: &mut ()) -> Self::Field {
		self.utxo_hash.hash([key, value], compiler)
	}

	#[inline]
	fn void_number(&self, key: &Self::Field, utxo: &Self::Field, compiler: &mut ()) -> Self::Field {
		self.void_number_hash.hash([key, utxo], compiler)
	}

	#[inline]
	fn assert_membership(
		&self,
		utxo: &Self::Field,
		root: &Self::Field,
		membership_proof: &Self::MembershipProof,
		_: &mut (),
	) {
		assert!(self.merkle_tree_parameters.verify_path(membership_proof, root, utxo))
	}
}

pub struct ParametersVar {
	pub utxo_hash: Poseidon2Var,
	pub void_number_hash: Poseidon2Var,
	pub merkle_tree_parameters: merkle_tree::Parameters<MerkleTreeConfiguration, Compiler>,
}

impl circuit::Parameters<Compiler> for ParametersVar {
	type Field = ScalarVar;
	type MembershipProof = PathVar<MerkleTreeConfiguration, Compiler>;

	#[inline]
	fn assert_eq(&self, lhs: &Self::Field, rhs: &Self::Field, compiler: &mut Compiler) {
		compiler.assert_eq(lhs, rhs)
	}

	#[inline]
	fn utxo(&self, key: &Self::Field, value: &Self::Field, compiler: &mut Compiler) -> Self::Field {
		self.utxo_hash.hash([key, value], compiler)
	}

	#[inline]
	fn void_number(
		&self,
		key: &Self::Field,
		utxo: &Self::Field,
		compiler: &mut Compiler,
	) -> Self::Field {
		self.void_number_hash.hash([key, utxo], compiler)
	}

	#[inline]
	fn assert_membership(
		&self,
		utxo: &Self::Field,
		root: &Self::Field,
		membership_proof: &Self::MembershipProof,
		compiler: &mut Compiler,
	) {
		let is_valid =
			self.merkle_tree_parameters
				.verify_path_with(membership_proof, root, utxo, compiler);
		compiler.assert(&is_valid);
	}
}

impl Constant<Compiler> for ParametersVar {
	type Type = Parameters;

	#[inline]
	fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
		Self {
			utxo_hash: this.utxo_hash.as_constant(compiler),
			void_number_hash: this.void_number_hash.as_constant(compiler),
			merkle_tree_parameters: this.merkle_tree_parameters.as_constant(compiler),
		}
	}
}

pub struct Accumulator(merkle_tree::full::FullMerkleTree<MerkleTreeConfiguration>);

impl accumulator::Accumulator<Scalar> for Accumulator {
	type Root = Scalar;
	type MembershipProof = Path<MerkleTreeConfiguration>;

	#[inline]
	fn insert(&mut self, item: Scalar) {
		self.0.push(&item);
	}

	#[inline]
	fn membership_proof(&self, item: &Scalar) -> Option<(Self::Root, Self::MembershipProof)> {
		Some((*self.0.root(), self.0.path(self.0.position(&self.0.parameters.digest(item))?).ok()?))
	}
}

pub struct Config;

impl Configuration for Config {
	type Compiler = Compiler;
	type ProvingKey = ProvingKey;
	type VerifyingKey = VerifyingKey;
	type Proof = Proof;
	type Error = <Self::ProofSystem as proofsystem::ProofSystem>::Error;
	type ProofSystem = ProofSystem;
	type Field = Scalar;
	type MembershipProof = Path<MerkleTreeConfiguration>;
	type Parameters = Parameters;
	type Accumulator = Accumulator;
	type FieldVar = ScalarVar;
	type MembershipProofVar = PathVar<MerkleTreeConfiguration, Compiler>;
	type ParametersVar = ParametersVar;
}

pub type ProofSystem = Groth16<Pairing>;
pub type ProvingKey = <ProofSystem as proofsystem::ProofSystem>::ProvingKey;
pub type VerifyingKey = <ProofSystem as proofsystem::ProofSystem>::VerifyingKey;
pub type Proof = <ProofSystem as proofsystem::ProofSystem>::Proof;

/// Raw Types
pub mod types {
	pub type Key = [u8; 32];
	pub type Utxo = [u8; 32];
	pub type VoidNumber = [u8; 32];
	pub type Balance = u64;
	pub type ZKP = [u8; 192];
	pub type MerkleRoot = [u8; 32];
	pub type HashDigest = [u8; 32];

	pub const MERKLE_TREE_DEPTH: usize = super::MERKLE_TREE_HEIGHT;
}

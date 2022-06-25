//! Subtornado Configuration

use crate::{
	circuit::{self, Configuration},
	crypto::{
		accumulator,
		arkworks::{FpVar, R1CS},
		eclair::alloc::Constant,
		merkle_tree::{self, path::Path},
		proofsystem::{arkworks::Groth16, ProofSystem},
	},
};

/// Merkle Tree Height
pub const MERKLE_TREE_HEIGHT: usize = 20;

///
pub type Pairing = ark_bls12_381::Bls12_381;

///
pub type Scalar = ark_bls12_381::Fr;

///
pub type ScalarVar = FpVar<Scalar>;

///
pub type Compiler = R1CS<Scalar>;

///
pub struct MerkleTreeInnerHash;

impl merkle_tree::InnerHash for MerkleTreeInnerHash {
	type LeafDigest = Scalar;
	type Parameters = ();
	type Output = Scalar;

	#[inline]
	fn join(
		parameters: &Self::Parameters,
		lhs: &Self::Output,
		rhs: &Self::Output,
		compiler: &mut (),
	) -> Self::Output {
		todo!()
	}

	#[inline]
	fn join_leaves(
		parameters: &Self::Parameters,
		lhs: &Self::LeafDigest,
		rhs: &Self::LeafDigest,
		compiler: &mut (),
	) -> Self::Output {
		todo!()
	}
}

///
pub struct MerkleTreeInnerHashVar;

impl merkle_tree::InnerHash<Compiler> for MerkleTreeInnerHashVar {
	type LeafDigest = ScalarVar;
	type Parameters = ();
	type Output = ScalarVar;

	#[inline]
	fn join(
		parameters: &Self::Parameters,
		lhs: &Self::Output,
		rhs: &Self::Output,
		compiler: &mut Compiler,
	) -> Self::Output {
		todo!()
	}

	#[inline]
	fn join_leaves(
		parameters: &Self::Parameters,
		lhs: &Self::LeafDigest,
		rhs: &Self::LeafDigest,
		compiler: &mut Compiler,
	) -> Self::Output {
		todo!()
	}
}

///
pub struct MerkleTreeConfiguration;

impl merkle_tree::HashConfiguration for MerkleTreeConfiguration {
	type LeafHash = merkle_tree::IdentityLeafHash<Scalar>;
	type InnerHash = MerkleTreeInnerHash;
}

impl merkle_tree::Configuration for MerkleTreeConfiguration {
	const HEIGHT: usize = MERKLE_TREE_HEIGHT;
}

///
pub struct Parameters;

impl circuit::Parameters for Parameters {
	type Field = Scalar;
	type MembershipProof = Path<MerkleTreeConfiguration>;

	#[inline]
	fn assert_eq(&self, lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) {
		assert_eq!(lhs, rhs)
	}

	#[inline]
	fn utxo(&self, key: &Self::Field, value: &Self::Field, _: &mut ()) -> Self::Field {
		todo!()
	}

	#[inline]
	fn void_number(&self, key: &Self::Field, utxo: &Self::Field, _: &mut ()) -> Self::Field {
		todo!()
	}

	#[inline]
	fn assert_membership(
		&self,
		utxo: &Self::Field,
		root: &Self::Field,
		membership_proof: &Self::MembershipProof,
		_: &mut (),
	) {
		todo!()
	}
}

///
pub struct ParametersVar;

impl circuit::Parameters<Compiler> for ParametersVar {
	type Field = ScalarVar;
	type MembershipProof = ();

	#[inline]
	fn assert_eq(&self, lhs: &Self::Field, rhs: &Self::Field, compiler: &mut Compiler) {
		todo!()
	}

	#[inline]
	fn utxo(&self, key: &Self::Field, value: &Self::Field, compiler: &mut Compiler) -> Self::Field {
		todo!()
	}

	#[inline]
	fn void_number(
		&self,
		key: &Self::Field,
		utxo: &Self::Field,
		compiler: &mut Compiler,
	) -> Self::Field {
		todo!()
	}

	#[inline]
	fn assert_membership(
		&self,
		utxo: &Self::Field,
		root: &Self::Field,
		membership_proof: &Self::MembershipProof,
		compiler: &mut Compiler,
	) {
		todo!()
	}
}

impl Constant<Compiler> for ParametersVar {
	type Type = Parameters;

	#[inline]
	fn new_constant(this: &Self::Type, compiler: &mut Compiler) -> Self {
		todo!()
	}
}

///
pub struct Accumulator;

impl accumulator::Accumulator<Scalar> for Accumulator {
	type Root = Scalar;
	type MembershipProof = Path<MerkleTreeConfiguration>;

	#[inline]
	fn insert(&mut self, item: Scalar) {
		todo!()
	}

	#[inline]
	fn membership_proof(&self, item: &Scalar) -> Option<(Self::Root, Self::MembershipProof)> {
		todo!()
	}
}

/*

///
pub struct Config;

impl Configuration for Config {
	type Compiler = Compiler;
	type ProvingKey = <Self::ProofSystem as ProofSystem>::ProvingKey;
	type VerifyingKey = <Self::ProofSystem as ProofSystem>::VerifyingKey;
	type Proof = <Self::ProofSystem as ProofSystem>::Proof;
	type Error = <Self::ProofSystem as ProofSystem>::Error;
	type ProofSystem = Groth16<Pairing>;
	type Field = Scalar;
	type MembershipProof = Path<MerkleTreeConfiguration>;
	type Parameters = Parameters;
	type Accumulator = Accumulator;
	type FieldVar = ScalarVar;
	type MembershipProofVar = ();
	type ParametersVar = ParametersVar;
}

*/

//! Poseidon Hash Function

use alloc::vec::Vec;
use core::{iter, mem};

/// Field Element
pub trait Field {
	/// Returns the additive identity of the field.
	fn zero() -> Self;

	/// Checks if the field element equals the result of calling [`zero`](Self::zero).
	fn is_zero(&self) -> bool;

	/// Returns the multiplicative identity of the field.
	fn one() -> Self;

	/// Adds two field elements together.
	fn add(lhs: &Self, rhs: &Self) -> Self;

	/// Adds the `rhs` field element to the `self` field element, storing the value in `self`.
	fn add_assign(&mut self, rhs: &Self);

	/// Multiplies two field elements together.
	fn mul(lhs: &Self, rhs: &Self) -> Self;

	/// Subtracts `rhs` from `lhs`.
	fn sub(lhs: &Self, rhs: &Self) -> Self;

	/// Computes the multiplicative inverse of a field element.
	fn inverse(&self) -> Option<Self>
	where
		Self: Sized;
}

/// Field Element Generation
pub trait FieldGeneration {
	/// Number of bits of modulus of the field.
	const MODULUS_BITS: usize;

	/// Converts a `u64` value to a field element.
	fn from_u64(elem: u64) -> Self;

	/// Converts from `bits` into a field element in big endian order, returning `None` if `bits`
	/// are out of range.
	fn try_from_bits_be(bits: &[bool]) -> Option<Self>
	where
		Self: Sized;
}

/// Poseidon Permutation Specification
pub trait Specification<COM = ()> {
	/// Field Type used for Permutation State
	type Field;

	/// Field Type used for Constant Parameters
	type ParameterField;

	/// Number of Partial Rounds
	const PARTIAL_ROUNDS: usize;

	/// Number of Full Rounds
	///
	/// The total number of full rounds in Poseidon Hash, including the first set
	/// of full rounds and then the second set after the partial rounds.
	const FULL_ROUNDS: usize;

	/// Returns the domain tag for `arity`. We use different domain tags for different applications
	/// to defend against rainbow table attacks.
	fn domain_tag(arity: usize, compiler: &mut COM) -> Self::Field;

	/// Adds two field elements together.
	fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

	/// Adds a field element `lhs` with a constant `rhs`
	fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

	/// Multiplies two field elements together.
	fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

	/// Multiplies a field element `lhs` with a constant `rhs`
	fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

	/// Adds the `rhs` field element to `lhs` field element, updating the value in `lhs`
	fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut COM);

	/// Adds the `rhs` constant to `lhs` field element, updating the value in `lhs`
	fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, compiler: &mut COM);

	/// Applies the S-BOX to `point`.
	fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);
}

/// Poseidon State Vector
type State<S, COM> = Vec<<S as Specification<COM>>::Field>;

/// Returns the total number of rounds in a Poseidon permutation.
#[inline]
pub fn rounds<S, COM>() -> usize
where
	S: Specification<COM>,
{
	S::FULL_ROUNDS + S::PARTIAL_ROUNDS
}

/// Poseidon Hasher
pub struct Hasher<S, const ARITY: usize, COM = ()>
where
	S: Specification<COM>,
{
	/// Additive Round Keys
	additive_round_keys: Vec<S::ParameterField>,

	/// MDS Matrix
	mds_matrix: Vec<S::ParameterField>,
}

impl<S, const ARITY: usize, COM> Hasher<S, ARITY, COM>
where
	S: Specification<COM>,
{
	/// Width of the State Buffer
	pub const WIDTH: usize = ARITY + 1;

	/// Half Number of Full Rounds
	///
	/// Poseidon Hash first has [`HALF_FULL_ROUNDS`]-many full rounds in the beginning,
	/// followed by [`PARTIAL_ROUNDS`]-many partial rounds in the middle, and finally
	/// [`HALF_FULL_ROUNDS`]-many full rounds at the end.
	///
	/// [`HALF_FULL_ROUNDS`]: Self::HALF_FULL_ROUNDS
	/// [`PARTIAL_ROUNDS`]: Specification::PARTIAL_ROUNDS
	pub const HALF_FULL_ROUNDS: usize = S::FULL_ROUNDS / 2;

	/// Total Number of Rounds
	pub const ROUNDS: usize = S::FULL_ROUNDS + S::PARTIAL_ROUNDS;

	/// Number of Entries in the MDS Matrix
	pub const MDS_MATRIX_SIZE: usize = Self::WIDTH * Self::WIDTH;

	/// Total Number of Additive Rounds Keys
	pub const ADDITIVE_ROUND_KEYS_COUNT: usize = Self::ROUNDS * Self::WIDTH;

	/// Builds a new [`Hasher`] from `additive_round_keys` and `mds_matrix`.
	///
	/// # Panics
	///
	/// This method panics if the input vectors are not the correct size for the specified
	/// [`Specification`].
	#[inline]
	pub fn new(
		additive_round_keys: Vec<S::ParameterField>,
		mds_matrix: Vec<S::ParameterField>,
	) -> Self {
		assert_eq!(
			additive_round_keys.len(),
			Self::ADDITIVE_ROUND_KEYS_COUNT,
			"Additive Rounds Keys are not the correct size."
		);
		assert_eq!(mds_matrix.len(), Self::MDS_MATRIX_SIZE, "MDS Matrix is not the correct size.");
		Self::new_unchecked(additive_round_keys, mds_matrix)
	}

	/// Builds a new [`Hasher`] from `additive_round_keys` and `mds_matrix` without
	/// checking their sizes.
	#[inline]
	fn new_unchecked(
		additive_round_keys: Vec<S::ParameterField>,
		mds_matrix: Vec<S::ParameterField>,
	) -> Self {
		Self { additive_round_keys, mds_matrix }
	}

	/// Returns the additive keys for the given `round`.
	#[inline]
	fn additive_keys(&self, round: usize) -> &[S::ParameterField] {
		let width = Self::WIDTH;
		let start = round * width;
		&self.additive_round_keys[start..start + width]
	}

	/// Computes the MDS matrix multiplication against the `state`.
	#[inline]
	fn mds_matrix_multiply(&self, state: &mut State<S, COM>, compiler: &mut COM) {
		let width = Self::WIDTH;
		let mut next = Vec::with_capacity(width);
		for i in 0..width {
			// NOTE: clippy false-positive: Without `collect`, the two closures in `map` and
			//       `reduce` will have simultaneous `&mut` access to `compiler`. Adding `collect`
			//       allows `map` to be done before `reduce`.
			#[allow(clippy::needless_collect)]
			let linear_combination = state
				.iter()
				.enumerate()
				.map(|(j, elem)| S::mul_const(elem, &self.mds_matrix[width * i + j], compiler))
				.collect::<Vec<_>>();
			next.push(
				linear_combination
					.into_iter()
					.reduce(|acc, next| S::add(&acc, &next, compiler))
					.unwrap(),
			);
		}
		mem::swap(&mut next, state);
	}

	/// Computes the first round of the Poseidon permutation from `trapdoor` and `input`.
	#[inline]
	fn first_round(&self, input: [&S::Field; ARITY], compiler: &mut COM) -> State<S, COM> {
		let mut state = Vec::with_capacity(Self::WIDTH);
		for (i, point) in iter::once(&S::domain_tag(ARITY, compiler)).chain(input).enumerate() {
			let mut elem = S::add_const(point, &self.additive_round_keys[i], compiler);
			S::apply_sbox(&mut elem, compiler);
			state.push(elem);
		}
		self.mds_matrix_multiply(&mut state, compiler);
		state
	}

	/// Computes a full round at the given `round` index on the internal permutation `state`.
	#[inline]
	fn full_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
		let keys = self.additive_keys(round);
		for (i, elem) in state.iter_mut().enumerate() {
			S::add_const_assign(elem, &keys[i], compiler);
			S::apply_sbox(elem, compiler);
		}
		self.mds_matrix_multiply(state, compiler);
	}

	/// Computes a partial round at the given `round` index on the internal permutation `state`.
	#[inline]
	fn partial_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
		let keys = self.additive_keys(round);
		for (i, elem) in state.iter_mut().enumerate() {
			S::add_const_assign(elem, &keys[i], compiler);
		}
		S::apply_sbox(&mut state[0], compiler);
		self.mds_matrix_multiply(state, compiler);
	}

	/// Computes the hash over `input` in the given `compiler` and returns the untruncated state.
	#[inline]
	fn hash_untruncated(&self, input: [&S::Field; ARITY], compiler: &mut COM) -> Vec<S::Field> {
		let mut state = self.first_round(input, compiler);
		for round in 1..Self::HALF_FULL_ROUNDS {
			self.full_round(round, &mut state, compiler);
		}
		for round in Self::HALF_FULL_ROUNDS..(Self::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS) {
			self.partial_round(round, &mut state, compiler);
		}
		for round in
			(Self::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS)..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
		{
			self.full_round(round, &mut state, compiler);
		}
		state
	}

	/// Computes the hash over `input` in the given `compiler`.
	#[inline]
	pub fn hash(&self, input: [&S::Field; ARITY], compiler: &mut COM) -> S::Field {
		let mut state = self.hash_untruncated(input, compiler);
		state.truncate(1);
		state.remove(0)
	}
}

/// Arkworks Backend
pub mod arkworks {
	use super::*;
	use crate::crypto::{
		alloc::Constant,
		arkworks::{Fp, R1CS},
	};
	use ark_ff::{BigInteger, Field, FpParameters, PrimeField};
	use ark_r1cs_std::{
		alloc::AllocVar,
		fields::{fp::FpVar, FieldVar},
	};

	/// Compiler Type
	type Compiler<S> = R1CS<<S as Specification>::Field>;

	/// Poseidon Permutation Specification.
	pub trait Specification {
		/// Field Type
		type Field: PrimeField;

		/// Number of Full Rounds
		///
		/// The total number of full rounds in Poseidon Hash, including the first set
		/// of full rounds and then the second set after the partial rounds.
		const FULL_ROUNDS: usize;

		/// Number of Partial Rounds
		const PARTIAL_ROUNDS: usize;

		/// S-BOX Exponenet
		const SBOX_EXPONENT: u64;
	}

	impl<F> super::Field for Fp<F>
	where
		F: PrimeField,
	{
		#[inline]
		fn zero() -> Self {
			Self(F::zero())
		}

		#[inline]
		fn is_zero(&self) -> bool {
			self.0 == F::zero()
		}

		#[inline]
		fn one() -> Self {
			Self(F::one())
		}

		#[inline]
		fn add(lhs: &Self, rhs: &Self) -> Self {
			Self(lhs.0 + rhs.0)
		}

		#[inline]
		fn add_assign(&mut self, rhs: &Self) {
			self.0 += rhs.0;
		}

		#[inline]
		fn sub(lhs: &Self, rhs: &Self) -> Self {
			Self(lhs.0 - rhs.0)
		}

		#[inline]
		fn mul(lhs: &Self, rhs: &Self) -> Self {
			Self(lhs.0 * rhs.0)
		}

		#[inline]
		fn inverse(&self) -> Option<Self> {
			self.0.inverse().map(Self)
		}
	}

	impl<F> FieldGeneration for Fp<F>
	where
		F: PrimeField,
	{
		const MODULUS_BITS: usize = F::Params::MODULUS_BITS as usize;

		#[inline]
		fn try_from_bits_be(bits: &[bool]) -> Option<Self> {
			F::from_repr(F::BigInt::from_bits_be(bits)).map(Self)
		}

		#[inline]
		fn from_u64(elem: u64) -> Self {
			Self(F::from(elem))
		}
	}

	impl<S> super::Specification for S
	where
		S: Specification,
	{
		type Field = Fp<S::Field>;
		type ParameterField = Fp<S::Field>;

		const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;
		const FULL_ROUNDS: usize = S::FULL_ROUNDS;

		#[inline]
		fn domain_tag(arity: usize, _: &mut ()) -> Self::Field {
			Fp(S::Field::from(((1 << arity) - 1) as u64))
		}

		#[inline]
		fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
			Fp(lhs.0 + rhs.0)
		}

		#[inline]
		fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
			Fp(lhs.0 + rhs.0)
		}

		#[inline]
		fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
			Fp(lhs.0 * rhs.0)
		}

		#[inline]
		fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
			Fp(lhs.0 * rhs.0)
		}

		#[inline]
		fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
			lhs.0 += rhs.0;
		}

		#[inline]
		fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut ()) {
			lhs.0 += rhs.0;
		}

		#[inline]
		fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
			point.0 = point.0.pow(&[Self::SBOX_EXPONENT, 0, 0, 0]);
		}
	}

	impl<S> super::Specification<Compiler<S>> for S
	where
		S: Specification,
	{
		type Field = FpVar<S::Field>;
		type ParameterField = Fp<S::Field>;

		const PARTIAL_ROUNDS: usize = S::PARTIAL_ROUNDS;
		const FULL_ROUNDS: usize = S::FULL_ROUNDS;

		#[inline]
		fn domain_tag(arity: usize, compiler: &mut Compiler<S>) -> Self::Field {
			FpVar::new_witness(compiler.cs.clone(), || {
				Ok(S::Field::from(((1 << arity) - 1) as u64))
			})
			.unwrap()
		}

		#[inline]
		fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
			lhs + rhs
		}

		#[inline]
		fn add_const(
			lhs: &Self::Field,
			rhs: &Self::ParameterField,
			_: &mut Compiler<S>,
		) -> Self::Field {
			lhs + FpVar::Constant(rhs.0)
		}

		#[inline]
		fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) -> Self::Field {
			lhs * rhs
		}

		#[inline]
		fn mul_const(
			lhs: &Self::Field,
			rhs: &Self::ParameterField,
			_: &mut Compiler<S>,
		) -> Self::Field {
			lhs * FpVar::Constant(rhs.0)
		}

		#[inline]
		fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut Compiler<S>) {
			*lhs += rhs;
		}

		#[inline]
		fn add_const_assign(
			lhs: &mut Self::Field,
			rhs: &Self::ParameterField,
			_: &mut Compiler<S>,
		) {
			*lhs += FpVar::Constant(rhs.0)
		}

		#[inline]
		fn apply_sbox(point: &mut Self::Field, _: &mut Compiler<S>) {
			*point = point
				.pow_by_constant(&[Self::SBOX_EXPONENT])
				.expect("Exponentiation is not allowed to fail.");
		}
	}

	impl<S, const ARITY: usize> Constant<Compiler<S>> for super::Hasher<S, ARITY, Compiler<S>>
	where
		S: Specification,
	{
		type Type = super::Hasher<S, ARITY>;

		#[inline]
		fn new_constant(this: &Self::Type, compiler: &mut Compiler<S>) -> Self {
			let _ = compiler;
			Self {
				additive_round_keys: this.additive_round_keys.clone(),
				mds_matrix: this.mds_matrix.clone(),
			}
		}
	}
}

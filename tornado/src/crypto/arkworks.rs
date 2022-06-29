//! Arkworks Backend

use crate::crypto::{
	eclair::{
		self,
		alloc::{
			mode::{Public, Secret},
			Constant, Variable,
		},
		bool::{Assert, AssertEq, ConditionalSwap},
		Has,
	},
	rand::{RngCore, Sample},
};
use ark_ff::{PrimeField, UniformRand};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, select::CondSelectGadget};
use ark_relations::{
	ns, r1cs as ark_r1cs,
	r1cs::{ConstraintSynthesizer, ConstraintSystemRef},
};

pub use ark_r1cs::SynthesisError;
pub use ark_r1cs_std::{bits::boolean::Boolean, fields::fp::FpVar};

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

/// Returns an empty variable assignment for setup mode.
///
/// # Warning
///
/// This does not work for all variable assignments! For some assignemnts, the variable inherits
/// some structure from its input, like its length or number of bits, which are only known at
/// run-time. For those cases, some mocking is required and this function can not be used directly.
#[inline]
pub fn empty<T>() -> SynthesisResult<T> {
	Err(SynthesisError::AssignmentMissing)
}

/// Returns a filled variable assignment with the given `value`.
#[inline]
pub fn full<T>(value: T) -> impl FnOnce() -> SynthesisResult<T> {
	move || Ok(value)
}

/// Field Element
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Fp<F>(pub F)
where
	F: PrimeField;

impl<F> Sample for Fp<F>
where
	F: PrimeField,
{
	#[inline]
	fn sample<R>(_: (), rng: &mut R) -> Self
	where
		R: RngCore + ?Sized,
	{
		Self(UniformRand::rand(rng))
	}
}

/// Arkworks Rank-1 Constraint System
pub struct R1CS<F>
where
	F: PrimeField,
{
	/// Constraint System
	pub(crate) cs: ark_r1cs::ConstraintSystemRef<F>,
}

impl<F> R1CS<F>
where
	F: PrimeField,
{
	/// Constructs a new constraint system which is ready for unknown variables.
	#[inline]
	pub fn for_compile() -> Self {
		// FIXME: This might not be the right setup for all proof systems.
		let cs = ark_r1cs::ConstraintSystem::new_ref();
		cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
		cs.set_mode(ark_r1cs::SynthesisMode::Setup);
		Self { cs }
	}

	/// Constructs a new constraint system which is ready for known variables.
	#[inline]
	pub fn for_prove() -> Self {
		// FIXME: This might not be the right setup for all proof systems.
		let cs = ark_r1cs::ConstraintSystem::new_ref();
		cs.set_optimization_goal(ark_r1cs::OptimizationGoal::Constraints);
		Self { cs }
	}
}

impl<F> ConstraintSynthesizer<F> for R1CS<F>
where
	F: PrimeField,
{
	/// Generates constraints for `self` by copying them into `cs`. This method is necessary to hook
	/// into the proof system traits defined in `arkworks`.
	#[inline]
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> SynthesisResult {
		let precomputed_cs = self
			.cs
			.into_inner()
			.expect("We own this constraint system so we can consume it.");
		let mut target_cs = cs
			.borrow_mut()
			.expect("This is given to us to mutate so it can't be borrowed by anyone else.");
		*target_cs = precomputed_cs;
		Ok(())
	}
}

impl<F> Has<bool> for R1CS<F>
where
	F: PrimeField,
{
	type Type = Boolean<F>;
}

impl<F> Assert for R1CS<F>
where
	F: PrimeField,
{
	#[inline]
	fn assert(&mut self, b: &Boolean<F>) {
		b.enforce_equal(&Boolean::TRUE)
			.expect("Enforcing equality is not allowed to fail.");
	}
}

impl<F> AssertEq for R1CS<F> where F: PrimeField {}

impl<F> Constant<R1CS<F>> for Boolean<F>
where
	F: PrimeField,
{
	type Type = bool;

	#[inline]
	fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
		AllocVar::new_constant(ns!(compiler.cs, "boolean constant"), this)
			.expect("Variable allocation is not allowed to fail.")
	}
}

impl<F> Variable<Public, R1CS<F>> for Boolean<F>
where
	F: PrimeField,
{
	type Type = bool;

	#[inline]
	fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
		Self::new_input(ns!(compiler.cs, "boolean public input"), full(this))
			.expect("Variable allocation is not allowed to fail.")
	}

	#[inline]
	fn new_unknown(compiler: &mut R1CS<F>) -> Self {
		Self::new_input(ns!(compiler.cs, "boolean public input"), empty::<bool>)
			.expect("Variable allocation is not allowed to fail.")
	}
}

impl<F> Variable<Secret, R1CS<F>> for Boolean<F>
where
	F: PrimeField,
{
	type Type = bool;

	#[inline]
	fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
		Self::new_witness(ns!(compiler.cs, "boolean secret witness"), full(this))
			.expect("Variable allocation is not allowed to fail.")
	}

	#[inline]
	fn new_unknown(compiler: &mut R1CS<F>) -> Self {
		Self::new_witness(ns!(compiler.cs, "boolean secret witness"), empty::<bool>)
			.expect("Variable allocation is not allowed to fail.")
	}
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for Boolean<F>
where
	F: PrimeField,
{
	#[inline]
	fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
		let _ = compiler;
		self.is_eq(rhs).expect("Equality checking is not allowed to fail.")
	}
}

impl<F> Constant<R1CS<F>> for FpVar<F>
where
	F: PrimeField,
{
	type Type = Fp<F>;

	#[inline]
	fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
		AllocVar::new_constant(ns!(compiler.cs, "field constant"), this.0)
			.expect("Variable allocation is not allowed to fail.")
	}
}

impl<F> Variable<Public, R1CS<F>> for FpVar<F>
where
	F: PrimeField,
{
	type Type = Fp<F>;

	#[inline]
	fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
		Self::new_input(ns!(compiler.cs, "field public input"), full(this.0))
			.expect("Variable allocation is not allowed to fail.")
	}

	#[inline]
	fn new_unknown(compiler: &mut R1CS<F>) -> Self {
		Self::new_input(ns!(compiler.cs, "field public input"), empty::<F>)
			.expect("Variable allocation is not allowed to fail.")
	}
}

impl<F> Variable<Secret, R1CS<F>> for FpVar<F>
where
	F: PrimeField,
{
	type Type = Fp<F>;

	#[inline]
	fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
		Self::new_witness(ns!(compiler.cs, "field secret witness"), full(this.0))
			.expect("Variable allocation is not allowed to fail.")
	}

	#[inline]
	fn new_unknown(compiler: &mut R1CS<F>) -> Self {
		Self::new_witness(ns!(compiler.cs, "field secret witness"), empty::<F>)
			.expect("Variable allocation is not allowed to fail.")
	}
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for FpVar<F>
where
	F: PrimeField,
{
	#[inline]
	fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
		let _ = compiler;
		self.is_eq(rhs).expect("Equality checking is not allowed to fail.")
	}
}

/// Conditionally select from `lhs` and `rhs` depending on the value of `bit`.
#[inline]
fn conditionally_select<F>(bit: &Boolean<F>, lhs: &FpVar<F>, rhs: &FpVar<F>) -> FpVar<F>
where
	F: PrimeField,
{
	FpVar::conditionally_select(bit, lhs, rhs)
		.expect("Conditionally selecting from two values is not allowed to fail.")
}

impl<F> ConditionalSwap<R1CS<F>> for FpVar<F>
where
	F: PrimeField,
{
	#[inline]
	fn swap(bit: &Boolean<F>, lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> (Self, Self) {
		let _ = compiler;
		(conditionally_select(bit, rhs, lhs), conditionally_select(bit, lhs, rhs))
	}
}

//! Arkworks Backend

use ark_ff::PrimeField;
use ark_relations::{
	r1cs as ark_r1cs,
	r1cs::{ConstraintSynthesizer, ConstraintSystemRef},
};

pub use ark_r1cs::SynthesisError;
pub use ark_r1cs_std::{bits::boolean::Boolean, fields::fp::FpVar};

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

///
#[derive(Clone)]
pub struct Fp<F>(pub F)
where
	F: PrimeField;

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

//! Accumulator Trait

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

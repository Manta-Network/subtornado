//! **_ECLAIR_**: Embedded Circuit Language And Intermediate Representation

pub mod alloc;
pub mod bool;
pub mod cmp;

/// Compiler Type Introspection
pub trait Has<T> {
	/// Compiler Type
	///
	/// This type represents the allocation of `T` into `Self` as a compiler. Whenever we need to
	/// define absractions that require the compiler to have access to some type internally, we can
	/// use this `trait` as a requirement of that abstraction.
	///
	/// See the [`bool`] module for an example of how to use introspection.
	type Type;
}

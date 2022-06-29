//! Utilities

/// Error Message for the [`into_array_unchecked`] and [`into_boxed_array_unchecked`] Functions
const INTO_UNCHECKED_ERROR_MESSAGE: &str =
	"Input did not have the correct length to match the output array of length";

/// Performs the [`TryInto`] conversion into an array without checking if the conversion succeeded.
#[inline]
pub fn into_array_unchecked<T, V, const N: usize>(value: V) -> [T; N]
where
	V: TryInto<[T; N]>,
{
	match value.try_into() {
		Ok(array) => array,
		_ => unreachable!("{} {:?}.", INTO_UNCHECKED_ERROR_MESSAGE, N),
	}
}

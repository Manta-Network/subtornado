// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Comparison

use crate::crypto::eclair::{bool::Bool, Has};

/// Partial Equivalence Relations
pub trait PartialEq<Rhs, COM>
where
	Rhs: ?Sized,
	COM: Has<bool> + ?Sized,
{
	/// Returns `true` if `self` and `rhs` are equal.
	fn eq(&self, rhs: &Rhs, compiler: &mut COM) -> Bool<COM>;
}

/* FIXME: We cannot implement this yet.
impl<T, Rhs> PartialEq<Rhs> for T
where
	T: cmp::PartialEq<Rhs>,
{
	#[inline]
	fn eq(&self, rhs: &Rhs, _: &mut ()) -> bool {
		self.eq(rhs)
	}

	#[inline]
	fn ne(&self, rhs: &Rhs, _: &mut ()) -> bool {
		self.ne(rhs)
	}
}
*/

/// Equality
pub trait Eq<COM>: PartialEq<Self, COM>
where
	COM: Has<bool>,
{
}

/* FIXME: We cannot implement this yet.
impl<T> Eq for T where T: cmp::Eq {}
*/

#![cfg_attr(not(feature = "std"), no_std)]

use codec::MaxEncodedLen;
pub use pallet::*;

/// Edit this file to define custom logic or remove it if it is not needed.
/// Learn more about FRAME and the core library of Substrate FRAME pallets:
/// <https://docs.substrate.io/v3/runtime/frame>
#[cfg(test)]
mod mock;

use frame_support::pallet_prelude::{Encode, Decode};
use scale_info::TypeInfo;

pub type Utxo = [u8; 32];
pub type VoidNumber = [u8; 32];
pub type Balance = u64;
pub type ZKP = [u8; 192];
pub type MerkleRoot = [u8; 32];
pub type HashDigest = [u8; 32];
pub const MERKLE_TREE_DEPTH: usize = 20;
pub const COIN_NOMINATION: Balance = 10;

#[derive(Clone, Debug, Decode, Default, Encode, MaxEncodedLen, Eq, PartialEq, TypeInfo)]
pub struct UtxoMerkleTreePath {
    /// Current Leaf Digest
    pub leaf_digest: Option<HashDigest>,

    /// Current Path
    pub current_path: CurrentPath,
}

/// Merkle Tree Current Path
#[derive(Clone, Debug, Decode, Default, Encode, Eq, PartialEq, TypeInfo)]
pub struct CurrentPath {
    /// Sibling Digest
    pub sibling_digest: HashDigest,

    /// Leaf Index
    pub leaf_index: u32,

    /// Inner Path
    pub inner_path: Vec<HashDigest>,
}

impl MaxEncodedLen for CurrentPath {
    #[inline]
    fn max_encoded_len() -> usize {
        0_usize
            .saturating_add(HashDigest::max_encoded_len())
            .saturating_add(u32::max_encoded_len())
            .saturating_add(
                // NOTE: We know that these paths don't exceed the path length.
                HashDigest::max_encoded_len().saturating_mul(MERKLE_TREE_DEPTH),
            )
    }
}

#[frame_support::pallet]
pub mod pallet {
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	use crate::{Utxo, VoidNumber, Balance, ZKP, MerkleRoot, UtxoMerkleTreePath, COIN_NOMINATION};

	/// Configure the pallet by specifying the parameters and types on which it depends.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	// Set of UTXOs
	#[pallet::storage]
	pub type UTXOSet<T> = 
		StorageMap<_, Twox64Concat, Utxo, (), ValueQuery>;

	// Set of VoidNumbers
	#[pallet::storage]
	pub type VoidNumberSet<T> = 
		StorageMap<_, Twox64Concat, VoidNumber, (), ValueQuery>;
	
	// Set of VoidNumbers
	#[pallet::storage]
	pub type UtxoInsertionOrder<T> = 
		StorageMap<_, Twox64Concat, u64, Utxo, ValueQuery>;
	
	// Public balance
	#[pallet::storage]
	pub type PublicBalance<T: Config> = 
		StorageMap<_, Twox64Concat, T::AccountId, Balance, ValueQuery>;
	
	#[pallet::storage]
	pub type Accumulator<T: Config> =
		StorageValue<_, (MerkleRoot, UtxoMerkleTreePath)>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		PublicCoinMint(T::AccountId, Balance),
		PublicTransfer(T::AccountId, T::AccountId, Balance),
		PrivateIOUMint(T::AccountId, Balance, Utxo, ZKP),
		PrivateIOUClaimed(T::AccountId, Balance),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// Error names should be descriptive.
		NoneValue,
		/// Sender doesn't have enough balance
		NotEnoughBalance,
		/// Duplicate UTXO
		DuplicateUtxo,
		/// Errors should have helpful documentation associated with them.
		StorageOverflow,
	}

	// Dispatchable functions allows users to interact with the pallet and invoke state changes.
	// These functions materialize as "extrinsics", which are often compared to transactions.
	// Dispatchable functions must be annotated with a weight and must return a DispatchResult.
	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10_000 + T::DbWeight::get().writes(1))]
		pub fn public_transfer(origin: OriginFor<T>, destination: T::AccountId, value: Balance) -> DispatchResult {
			let who = ensure_signed(origin)?;

			// Update storage.
			let sender_balance: Balance = match PublicBalance::<T>::try_get(&who) {
				Ok(balance) => balance,
				_ => 0u64,
			};

			if sender_balance < value {
				return Err(Error::<T>::NotEnoughBalance.into())
			}

			let receiver_balance = match PublicBalance::<T>::try_get(&destination) {
				Ok(balance) => balance,
				_ => 0u64,
			};

			PublicBalance::<T>::insert(&who, sender_balance - value);
			PublicBalance::<T>::insert(&destination, receiver_balance + value);

			// Emit an event.
			Self::deposit_event(Event::PublicTransfer(who, destination, value));
			Ok(())
		}

		/// An example dispatchable that may throw a custom error.
		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn mint_public_coin(origin: OriginFor<T>, value: Balance) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let previous_balance = match PublicBalance::<T>::try_get(&who){
				Ok(balance) => balance,
				_ => 0u64,
			};
			PublicBalance::<T>::insert(&who, previous_balance + value);
			Self::deposit_event(Event::PublicCoinMint(who, value));
			Ok(())
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn mint_private_iou(
			origin: OriginFor<T>, 
			utxo: Utxo, 
			proof: ZKP
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let previous_balance = match PublicBalance::<T>::try_get(&who){
				Ok(balance) => balance,
				_ => 0u64,
			};
			if previous_balance < COIN_NOMINATION {
				return Err(Error::<T>::NotEnoughBalance.into())
			}
			// TODO: verify ZKP
			ensure!(
				!UTXOSet::<T>::contains_key(utxo),
				Error::<T>::DuplicateUtxo
			);
			PublicBalance::<T>::insert(&who, previous_balance - COIN_NOMINATION);
			Self::deposit_event(Event::<T>::PrivateIOUMint(who, COIN_NOMINATION, utxo, proof));
			Ok(())
		}

		#[pallet::weight(10_000 + T::DbWeight::get().reads_writes(1,1))]
		pub fn claim_private_iou(
			origin: OriginFor<T>, 
			merkle_root: MerkleRoot,
			void_number: VoidNumber,
			proof: ZKP
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let previous_balance = match PublicBalance::<T>::try_get(&who){
				Ok(balance) => balance,
				_ => 0u64,
			};
			// verify ZKP

			PublicBalance::<T>::insert(&who, previous_balance + COIN_NOMINATION);
			Self::deposit_event(Event::<T>::PrivateIOUClaimed(who, COIN_NOMINATION));
			Ok(())
		}

	}
}

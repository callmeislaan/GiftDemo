#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod types;

#[frame_support::pallet]
pub mod pallet {

	pub use crate::types::*;
	use frame_support::{pallet_prelude::{*, OptionQuery}, Blake2_128Concat, ensure};
	use frame_system::pallet_prelude::*;
	use frame_support::sp_runtime::traits::Hash;
	use frame_support::inherent::Vec;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		type BrandSymbolLimit: Get<u32>;

		type BrandNameLimit: Get<u32>;

		type BrandLimit: Get<u32>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn brand_count)]
	pub type BrandCount<T> = StorageValue<_, u32, ValueQuery, >;

	#[pallet::storage]
	#[pallet::getter(fn brands)]
	pub type Brands<T: Config> = StorageMap<_, Blake2_128Concat, T::Hash, Brand<T>, OptionQuery, >;

	#[pallet::storage]
	#[pallet::getter(fn brand_symbols)]
	pub type BrandSymbols<T: Config> = StorageValue<_, BoundedVec<BrandSymbolType<T>, T::BrandLimit>, ValueQuery, >;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		BrandCreated(T::Hash, BrandSymbolType<T>),
	}

	#[pallet::error]
	pub enum Error<T> {
		BrandSymbolExisted,
		AppNumberLimited,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10_000 + T::DbWeight::get().writes(1))]
		pub fn create_new_brand(origin: OriginFor<T>, symbol: Vec<u8>, name: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;
			
			let bounded_symbol: BrandSymbolType<T> = symbol.clone().try_into().expect("symbol is too long");
			let bounded_name: BrandNameType<T> = name.clone().try_into().expect("name is too long");

			// ensure brand symbol not duplicate
			let brand_symbols = <BrandSymbols<T>>::get();
			ensure!(brand_symbols.contains(&bounded_symbol) == false, <Error<T>>::BrandSymbolExisted);

			let brand = Brand::new(bounded_symbol.clone(), bounded_name.clone(), who.clone());
			
			let brand_hash = T::Hashing::hash_of(&brand);

			// storage brand
			<Brands<T>>::insert(brand_hash.clone(), brand.clone());

			// storage brand symbols
			<BrandSymbols<T>>::mutate(|symbol_vec| {
				symbol_vec.try_push(bounded_symbol.clone())
			}).map_err(|_| <Error<T>>::AppNumberLimited)?;

			// increase and storage brand count
			let next_brand_count = Self::brand_count().checked_add(1_u32).ok_or(<Error<T>>::AppNumberLimited)?;

			<BrandCount<T>>::put(next_brand_count);

			Self::deposit_event(Event::BrandCreated(brand_hash, bounded_symbol));
			
			Ok(())
		}

	}
}

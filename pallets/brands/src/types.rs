use crate::Config;
use codec::*;
use frame_support::BoundedVec;
use scale_info::TypeInfo;

pub type BrandSymbolType<T> = BoundedVec<u8, <T as Config>::BrandSymbolLimit>;

pub type BrandNameType<T> = BoundedVec<u8, <T as Config>::BrandNameLimit>;

#[derive(Clone, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct Brand<T: Config> {
	symbol: BrandSymbolType<T>,
	name: BrandNameType<T>,
	owner: T::AccountId,
}

impl<T: Config> Brand<T> {
	pub fn new(symbol: BrandSymbolType<T>, name: BrandNameType<T>, owner: T::AccountId) -> Self {
		Brand { symbol, name, owner }
	}

	pub fn symbol(&self) -> BrandSymbolType<T> {
		self.symbol.clone()
	}

	pub fn name(&self) -> BrandNameType<T> {
		self.name.clone()
	}

	pub fn owner(&self) -> T::AccountId {
		self.owner.clone()
	}
}

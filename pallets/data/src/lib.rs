#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod crypto;
pub mod types;

#[frame_support::pallet]
pub mod pallet {
	pub use crate::crypto::*;
	pub use crate::types::*;

	use frame_support::inherent::Vec;
	use frame_support::pallet_prelude::{OptionQuery, *};
	use frame_support::{ensure, Blake2_128Concat, BoundedVec};
	use frame_system::offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer,
	};
	use frame_system::pallet_prelude::*;
	use serde_json::Deserializer;
	use sp_core::crypto::KeyTypeId;
	use sp_runtime::offchain::{http, Duration};

	/// Defines application identifier for crypto keys of this module.
	///
	/// Every module that deals with signatures needs to declare its unique identifier for
	/// its crypto keys.
	/// When an offchain worker is signing transactions it's going to request keys from type
	/// `KeyTypeId` via the keystore to sign the transaction.
	/// The keys can be inserted manually via RPC (see `author_insertKey`).
	pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"data");

	const UNSIGNED_TXS_PRIORITY: u64 = 100;
	const FETCH_TIMEOUT_PERIOD: u64 = 3000; // in milli-seconds
	const LOCK_TIMEOUT_EXPIRATION: u64 = FETCH_TIMEOUT_PERIOD + 1000; // in milli-seconds
	const LOCK_BLOCK_EXPIRATION: u32 = 3; // in block number
	const EXTERNAL_SERVER: &str = "http://localhost:9094";

	pub type DataPeer<T: Config> = BoundedVec<u8, T::PeerIdLimit>;

	#[pallet::config]
	pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		type PeerIdLimit: Get<u32>;

		/// The overarching dispatch call type.
		type Call: From<Call<Self>>;
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn account_peer)]
	pub type AccountPeer<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, DataPeer<T>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn peer_account)]
	pub type PeerAccount<T: Config> =
		StorageMap<_, Blake2_128Concat, DataPeer<T>, T::AccountId, OptionQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		DataPeerRegistered(T::AccountId, DataPeer<T>),
		DataPeerUpdated(T::AccountId, DataPeer<T>),
		DataPeerRemoved(DataPeer<T>),
	}

	#[pallet::error]
	pub enum Error<T> {
		NoneValue,
		StorageOverflow,
		HttpFetchingError,
		JsonParsingError,
		UnknownOffchainMux,
		AlreadyRegister,
		NeedRegister,
		OffchainSignedTxError,
		NoLocalAcctForSigning,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			log::info!("Hello from pallet-ocw.");
			Self::offchain_signed_tx(block_number);
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10_000)]
		pub fn register_data_peer(origin: OriginFor<T>, peer_id: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let bounded_peer_id: DataPeer<T> =
				peer_id.clone().try_into().expect("peer id is too long");

			ensure!(!<AccountPeer<T>>::contains_key(who.clone()), <Error<T>>::AlreadyRegister);
			ensure!(
				!<PeerAccount<T>>::contains_key(bounded_peer_id.clone()),
				<Error<T>>::AlreadyRegister
			);

			<AccountPeer<T>>::insert(who.clone(), bounded_peer_id.clone());
			<PeerAccount<T>>::insert(bounded_peer_id.clone(), who.clone());

			Self::deposit_event(<Event<T>>::DataPeerRegistered(who, bounded_peer_id));

			Ok(())
		}

		#[pallet::weight(10_000)]
		pub fn update_data_peer(origin: OriginFor<T>, peer_id: Vec<u8>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let bounded_peer_id: DataPeer<T> =
				peer_id.clone().try_into().expect("peer id is too long");

			ensure!(<AccountPeer<T>>::contains_key(who.clone()), <Error<T>>::NeedRegister);
			ensure!(
				<PeerAccount<T>>::contains_key(bounded_peer_id.clone()),
				<Error<T>>::NeedRegister
			);

			<AccountPeer<T>>::mutate(&who, |value| {
				*value = Some(bounded_peer_id.clone());
			});

			<PeerAccount<T>>::mutate(&bounded_peer_id, |value| {
				*value = Some(who.clone());
			});

			Self::deposit_event(<Event<T>>::DataPeerUpdated(who, bounded_peer_id));

			Ok(())
		}

		#[pallet::weight(0)]
		pub fn remove_data_peer(origin: OriginFor<T>, peers_id: Vec<Vec<u8>>) -> DispatchResult {
			let _ = ensure_signed(origin)?;

			for peer_id in peers_id {
				let bounded_peer_id: DataPeer<T> =
					peer_id.clone().try_into().expect("peer id is too long");
				// if let Some(bounded_peer_id) = bounded_peer_id_wrap {
				if <PeerAccount<T>>::contains_key(bounded_peer_id.clone()) {
					if let Some(account_id) = Self::peer_account(&bounded_peer_id) {
						<AccountPeer<T>>::remove(account_id);
					}

					<PeerAccount<T>>::remove(bounded_peer_id.clone());
					Self::deposit_event(<Event<T>>::DataPeerRemoved(bounded_peer_id));
				}
				// }
			}

			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn offchain_signed_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
			let peers_id = Self::fetch_peers_n_remove();

			// We retrieve a signer and check if it is valid.
			//   Since this pallet only has one key in the keystore. We use `any_account()1 to
			//   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
			let signer = Signer::<T, T::AuthorityId>::any_account();

			// Translating the current block number to number and submit it on-chain
			// let number: u64 = block_number.try_into().unwrap_or(0);

			// `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
			//   - `None`: no account is available for sending transaction
			//   - `Some((account, Ok(())))`: transaction is successfully sent
			//   - `Some((account, Err(())))`: error occured when sending the transaction
			let result = signer.send_signed_transaction(|_acct|
				// This is the on-chain function
				Call::remove_data_peer { peers_id: peers_id.clone(), });

			// Display error if the signed tx fails.
			if let Some((acc, res)) = result {
				if res.is_err() {
					log::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
					return Err(<Error<T>>::OffchainSignedTxError);
				}
				// Transaction is sent successfully
				return Ok(());
			}

			// The case of `None`: no account is available for sending
			log::error!("No local account available");
			Err(<Error<T>>::NoLocalAcctForSigning)
		}

		pub fn fetch_peers_n_remove() -> Vec<Vec<u8>> {
			let PEERS_URI = "http://localhost:9094/peers";

			let body = Self::fetch_from_remote(PEERS_URI).expect("Cannot fetch data");

			let body_str = sp_std::str::from_utf8(&body)
				.map_err(|_| <Error<T>>::JsonParsingError)
				.expect("Cannot parse json to string");

			// log::info!("{}", body_str);

			let stream = Deserializer::from_str(body_str).into_iter::<Option<Peer>>();

			let mut peers_id: Vec<Vec<u8>> = Vec::new();
			let peer_account = <PeerAccount<T>>::iter();
			let mut peers_need_remove: Vec<Vec<u8>> = Vec::new();

			for peer_wrap in stream {
				if let Some(peer) = peer_wrap.unwrap() {
					peers_id.push(peer.id);
				}
			}

			for (peer_id, _) in peer_account {
				if !peers_id.contains(&peer_id) {
					log::info!("peer id removed: {:?}", peer_id);
					peers_need_remove.push(peer_id.into());
				}
			}

			peers_need_remove
		}

		pub fn fetch_from_remote(server: &str) -> Result<Vec<u8>, Error<T>> {
			let request = http::Request::get(server);

			let timeout =
				sp_io::offchain::timestamp().add(Duration::from_millis(FETCH_TIMEOUT_PERIOD));

			let pending =
				request.deadline(timeout).send().map_err(|e| <Error<T>>::HttpFetchingError)?;

			let response = pending
				.try_wait(timeout)
				.map_err(|e| <Error<T>>::HttpFetchingError)?
				.map_err(|e| <Error<T>>::HttpFetchingError)?;

			ensure!(response.code == 200, <Error<T>>::HttpFetchingError);

			Ok(response.body().collect::<Vec<u8>>())
		}
	}
}

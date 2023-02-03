#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

pub mod crypto;
pub mod types;

#[frame_support::pallet]
pub mod pallet {
	pub use crate::crypto::*;
	pub use crate::types::*;

	use frame_support::inherent::Vec;
	use frame_support::pallet_prelude::*;
	use frame_support::unsigned::TransactionValidity;
	use frame_support::{ensure, Blake2_128Concat, BoundedVec};
	use frame_system as system;
	use frame_system::offchain::{
		AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer, SubmitTransaction,
	};
	use frame_system::pallet_prelude::*;
	use serde_json::Deserializer;
	use sp_core::crypto::KeyTypeId;
	use sp_runtime::offchain::{http, Duration};
	use sp_runtime::transaction_validity::{
		InvalidTransaction, TransactionPriority, TransactionSource, ValidTransaction,
	};

	/// Defines application identifier for crypto keys of this module.
	///
	/// Every module that deals with signatures needs to declare its unique identifier for
	/// its crypto keys.
	/// When an offchain worker is signing transactions it's going to request keys from type
	/// `KeyTypeId` via the keystore to sign the transaction.
	/// The keys can be inserted manually via RPC (see `author_insertKey`).
	pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"data");

	const FETCH_TIMEOUT_PERIOD: u64 = 3000; // in milli-seconds

	pub type BoundedPeerString<T> = BoundedVec<u8, <T as Config>::PeerStringLimit>;

	#[pallet::config]
	pub trait Config: frame_system::Config + CreateSignedTransaction<Call<Self>> {
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

		type PeerStringLimit: Get<u32>;

		type TrustedPeerLimit: Get<u32>;

		type CandidatePeerLimit: Get<u32>;

		type PeerLimit: Get<u32>;

		/// The overarching dispatch call type.
		type Call: From<Call<Self>>;
		/// The identifier type for an offchain worker.
		type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn peer_count)]
	pub type PeerCount<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn peer_info)]
	pub type PeerInfo<T: Config> =
		StorageMap<_, Blake2_128Concat, BoundedPeerString<T>, OnChainPeerInfo<T>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn provider_peer)]
	pub type ProviderPeer<T: Config> =
		StorageMap<_, Blake2_128Concat, T::AccountId, BoundedPeerString<T>, OptionQuery>;

	#[pallet::storage]
	#[pallet::getter(fn peers)]
	pub type Peers<T: Config> =
		StorageValue<_, BoundedVec<BoundedPeerString<T>, T::PeerLimit>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn candidate_peers)]
	pub type CandidatePeers<T: Config> =
		StorageValue<_, BoundedVec<BoundedPeerString<T>, T::CandidatePeerLimit>, ValueQuery>;

	#[pallet::storage]
	#[pallet::getter(fn trusted_peers)]
	pub type TrustedPeers<T: Config> =
		StorageValue<_, BoundedVec<BoundedPeerString<T>, T::TrustedPeerLimit>, ValueQuery>;

	/// Defines the block when next unsigned transaction will be accepted.
	///
	/// To prevent spam of unsigned (and unpayed!) transactions on the network,
	/// we only allow one transaction every `T::UnsignedInterval` blocks.
	/// This storage entry defines when new transaction is going to be accepted.
	#[pallet::storage]
	#[pallet::getter(fn next_unsigned_at)]
	pub(super) type NextUnsignedAt<T: Config> = StorageValue<_, T::BlockNumber, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		DataPeerRegistered(T::AccountId, BoundedPeerString<T>),
		TrustedDataPeerRegistered(T::AccountId, BoundedPeerString<T>),
		CandidateDataPeerRegistered(T::AccountId, BoundedPeerString<T>),
		DataPeerUpdated(T::AccountId, BoundedPeerString<T>),
		DataPeerRemoved(BoundedPeerString<T>),
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
		OffchainUnsignedTxError,
		TrustedPeerLimited,
		CandidatePeerLimited,
		UpdateDataPeerInfoError,
		AccountHasNoDataPeer,
		PeerLimited,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			log::info!("Hello from pallet-ocw.");
			Self::offchain_unsigned_tx(block_number);
		}
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		///
		/// By default unsigned transactions are disallowed, but implementing the validator
		/// here we make sure that some particular calls (the ones produced by offchain worker)
		/// are being whitelisted and marked as valid.
		fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			// ensure transaction come from local

			log::info!("Data source: {:?}", source);
			ensure!(source != TransactionSource::External, { InvalidTransaction::Custom(3) });

			if let Call::remove_data_peer_unsigned { block_number, peers_id } = call {
				Self::validate_transaction_parameters(block_number, peers_id)
			} else {
				InvalidTransaction::Call.into()
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(10_000)]
		pub fn register_trusted_data_peer(
			origin: OriginFor<T>,
			params: PeerInfoParameters,
		) -> DispatchResult {
			let _root = ensure_root(origin.clone());

			let who = ensure_signed(origin)?;

			let bounded_cluster_id = Self::register_data_node(who.clone(), params)?;

			// storage to trusted peers
			<TrustedPeers<T>>::try_mutate(|trusted_peers| {
				trusted_peers.try_push(bounded_cluster_id.clone())
			})
			.map_err(|_| <Error<T>>::TrustedPeerLimited)?;

			Self::deposit_event(<Event<T>>::TrustedDataPeerRegistered(who, bounded_cluster_id));

			Ok(())
		}

		#[pallet::weight(10_000)]
		pub fn register_candidate_data_peer(
			origin: OriginFor<T>,
			params: PeerInfoParameters,
		) -> DispatchResult {

			let who = ensure_signed(origin)?;

			let bounded_cluster_id = Self::register_data_node(who.clone(), params)?;

			// storage to candidate peers
			<CandidatePeers<T>>::try_mutate(|candidate_peers| {
				candidate_peers.try_push(bounded_cluster_id.clone())
			})
			.map_err(|_| <Error<T>>::CandidatePeerLimited)?;

			Self::deposit_event(<Event<T>>::CandidateDataPeerRegistered(who, bounded_cluster_id));

			Ok(())
		}

		#[pallet::weight(10_000)]
		pub fn update_data_peer_info(
			origin: OriginFor<T>,
			params: UpdatablePeerInfoParameters,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;

			let (bounded_cluster_public_address, bounded_ipfs_public_address) =
				Self::get_peer_info_value_from_updatable_param(params)?;

			let peer_id = Self::provider_peer(&who);

			ensure!(peer_id.is_some(), <Error<T>>::AccountHasNoDataPeer);

			<PeerInfo<T>>::try_mutate(&peer_id.clone().unwrap(), |peer_option| {
				if let Some(peer) = peer_option {
					peer.cluster_public_address = bounded_cluster_public_address.clone();
					peer.ipfs_public_address = bounded_ipfs_public_address.clone();
					Ok(())
				} else {
					Err(())
				}
			})
			.map_err(|_| <Error<T>>::UpdateDataPeerInfoError)?;

			Self::deposit_event(<Event<T>>::DataPeerUpdated(who, peer_id.clone().unwrap()));

			Ok(())
		}

		#[pallet::weight(10_000)]
		pub fn remove_data_peer(origin: OriginFor<T>, cluster_id: Vec<u8>) -> DispatchResult {
			let _root = ensure_root(origin.clone())?;

			let who = ensure_signed(origin)?;

			Ok(())
		}

		// for off-chain worker

		#[pallet::weight(0)]
		pub fn register_data_peer(
			origin: OriginFor<T>,
			params: PeerInfoParameters,
		) -> DispatchResult {
			let _ = ensure_none(origin)?;

			// let next_peer_count =
			// Self::peer_count().checked_add(1_u32.into()).ok_or(<Error<T>>::PeerLimited)?;
			// // increase peer count
			// <PeerCount<T>>::put(next_peer_count);

			// let bounded_cluster_id = Self::register_data_node(who.clone(), params)?;
			// Self::deposit_event(<Event<T>>::DataPeerRegistered(who, bounded_cluster_id));
			Ok(())
		}

		#[pallet::weight(0)]
		pub fn remove_data_peer_unsigned(
			origin: OriginFor<T>,
			_block_number: T::BlockNumber,
			peers_id: Vec<Vec<u8>>,
		) -> DispatchResult {
			let _ = ensure_none(origin)?;
			// for peer_id in peers_id {

			// 	let bounded_peer_id: BoundedPeerString<T> =
			// 		peer_id.clone().try_into().expect("peer id is too long");

			// 	if <PeerAccount<T>>::contains_key(bounded_peer_id.clone()) {
			// 		if let Some(account_id) = Self::peer_account(&bounded_peer_id) {
			// 			<ProviderPeer<T>>::remove(account_id);
			// 		}

			// 		<PeerAccount<T>>::remove(bounded_peer_id.clone());
			// 		Self::deposit_event(<Event<T>>::DataPeerRemoved(bounded_peer_id));
			// 	}
			// }

			Ok(())
		}
	}

	impl<T: Config> Pallet<T> {
		fn get_peer_info_value_from_updatable_param(
			params: UpdatablePeerInfoParameters,
		) -> Result<(Option<BoundedPeerString<T>>, Option<BoundedPeerString<T>>), Error<T>> {
			let mut bounded_cluster_public_address: Option<BoundedPeerString<T>> = None;
			let mut bounded_ipfs_public_address: Option<BoundedPeerString<T>> = None;

			if params.cluster_public_address.is_some() {
				bounded_cluster_public_address = Some(
					params
						.cluster_public_address
						.clone()
						.unwrap()
						.try_into()
						.expect("cluster public address is too long"),
				);
			}

			if params.ipfs_public_address.is_some() {
				bounded_ipfs_public_address = Some(
					params
						.ipfs_public_address
						.clone()
						.unwrap()
						.try_into()
						.expect("ipfs public address is too long"),
				);
			}

			Ok((bounded_cluster_public_address, bounded_ipfs_public_address))
		}

		fn get_peer_info_value_from_param(
			params: PeerInfoParameters,
		) -> Result<
			(BoundedPeerString<T>, Option<BoundedPeerString<T>>, Option<BoundedPeerString<T>>),
			Error<T>,
		> {
			let bounded_cluster_id: BoundedPeerString<T> =
				params.cluster_id.clone().try_into().expect("cluster id is too long");
				let mut bounded_cluster_public_address: Option<BoundedPeerString<T>> = None;
				let mut bounded_ipfs_public_address: Option<BoundedPeerString<T>> = None;
				if params.cluster_public_address.is_some() {
					bounded_cluster_public_address = Some(
						params
							.cluster_public_address
							.clone()
							.unwrap()
							.try_into()
							.expect("cluster public address is too long"),
					);
				}
	
				if params.ipfs_public_address.is_some() {
					bounded_ipfs_public_address = Some(
						params
							.ipfs_public_address
							.clone()
							.unwrap()
							.try_into()
							.expect("ipfs public address is too long"),
					);
				}
			Ok((bounded_cluster_id, bounded_cluster_public_address, bounded_ipfs_public_address))
		}

		fn prepare_peer_to_persist(
			who: T::AccountId,
			params: PeerInfoParameters,
		) -> Result<OnChainPeerInfo<T>, Error<T>> {
			let (bounded_cluster_id, bounded_cluster_public_address, bounded_ipfs_public_address) =
				Self::get_peer_info_value_from_param(params)?;

			ensure!(!<ProviderPeer<T>>::contains_key(who.clone()), <Error<T>>::AlreadyRegister);

			ensure!(
				!<PeerInfo<T>>::contains_key(bounded_cluster_id.clone()),
				<Error<T>>::AlreadyRegister
			);

			let current_block_number = <frame_system::Pallet<T>>::block_number();

			let peer_info = OnChainPeerInfo {
				cluster_id: bounded_cluster_id.clone(),
				cluster_public_address: bounded_cluster_public_address.clone(),
				ipfs_public_address: bounded_ipfs_public_address.clone(),
				create_at: current_block_number,
				provider: who.clone(),
			};

			Ok(peer_info)
		}

		fn register_data_node(
			who: T::AccountId,
			params: PeerInfoParameters,
		) -> Result<BoundedPeerString<T>, Error<T>> {
			let peer_info = Self::prepare_peer_to_persist(who.clone(), params.clone())?;

			let peer_id = peer_info.clone().cluster_id;

			<ProviderPeer<T>>::insert(who.clone(), peer_id.clone());
			<PeerInfo<T>>::insert(peer_id.clone(), peer_info.clone());

			Ok(peer_id.clone())
		}

		fn offchain_signed_tx() -> Result<(), Error<T>> {
			let peers_id = Self::fetch_peers_n_remove();

			// if peers_id.len() <= 0 {
			// 	return Ok(());
			// }

			// // We retrieve a signer and check if it is valid.
			// //   Since this pallet only has one key in the keystore. We use `any_account()1 to
			// //   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
			// let signer = Signer::<T, T::AuthorityId>::any_account();

			// // Translating the current block number to number and submit it on-chain
			// // let number: u64 = block_number.try_into().unwrap_or(0);

			// // `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
			// //   - `None`: no account is available for sending transaction
			// //   - `Some((account, Ok(())))`: transaction is successfully sent
			// //   - `Some((account, Err(())))`: error occured when sending the transaction
			// let result = signer.send_signed_transaction(|_acct|
			// 	// This is the on-chain function
			// 	Call::remove_data_peer { peers_id: peers_id.clone(), });

			// // Display error if the signed tx fails.
			// if let Some((acc, res)) = result {
			// 	if res.is_err() {
			// 		log::error!("failure: offchain_signed_tx: tx sent: {:?}", acc.id);
			// 		return Err(<Error<T>>::OffchainSignedTxError);
			// 	}
			// 	// Transaction is sent successfully
			// 	return Ok(());
			// }

			// The case of `None`: no account is available for sending
			log::error!("No local account available");
			Err(<Error<T>>::NoLocalAcctForSigning)
		}

		fn offchain_unsigned_tx(block_number: T::BlockNumber) -> Result<(), Error<T>> {
			let peers_id = Self::fetch_peers_n_remove();

			if peers_id.len() <= 0 {
				return Ok(());
			}

			let call = Call::remove_data_peer_unsigned { block_number, peers_id: peers_id.clone() };

			SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()).map_err(
				|_| {
					log::error!("Failed in offchain_unsigned_tx");
					<Error<T>>::OffchainUnsignedTxError
				},
			)
		}

		pub fn fetch_peers_n_remove() -> Vec<Vec<u8>> {
			// let PEERS_URI = "http://localhost:9094/peers";

			// let body = Self::fetch_from_remote(PEERS_URI).expect("Cannot fetch data");

			// let body_str = sp_std::str::from_utf8(&body)
			// 	.map_err(|_| <Error<T>>::JsonParsingError)
			// 	.expect("Cannot parse json to string");

			// // log::info!("{}", body_str);

			// let stream = Deserializer::from_str(body_str).into_iter::<Option<Peer>>();

			// let mut peers_id: Vec<Vec<u8>> = Vec::new();
			// let peer_account = <PeerAccount<T>>::iter();
			let mut peers_need_remove: Vec<Vec<u8>> = Vec::new();

			// for peer_wrap in stream {
			// 	if let Some(peer) = peer_wrap.unwrap() {
			// 		peers_id.push(peer.id);
			// 	}
			// }

			// for (peer_id, _) in peer_account {
			// 	if !peers_id.contains(&peer_id) {
			// 		log::info!("peer id removed: {:?}", peer_id);
			// 		peers_need_remove.push(peer_id.into());
			// 	}
			// }

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

		fn validate_transaction_parameters(
			block_number: &T::BlockNumber,
			peers_id: &Vec<Vec<u8>>,
		) -> TransactionValidity {
			log::info!("Validate transaction parameters");

			// Now let's check if the transaction has any chance to succeed.
			let next_unsigned_at = <NextUnsignedAt<T>>::get();
			if &next_unsigned_at > block_number {
				return InvalidTransaction::Stale.into();
			}
			// Let's make sure to reject transactions from the future.
			let current_block = <system::Pallet<T>>::block_number();
			if &current_block < block_number {
				return InvalidTransaction::Future.into();
			}

			ValidTransaction::with_tag_prefix("ExampleOffchainWorker")
				.priority(TransactionPriority::max_value())
				// This transaction does not require anything else to go before into the pool.
				// In theory we could require `previous_unsigned_at` transaction to go first,
				// but it's not necessary in our case.
				//.and_requires()
				// We set the `provides` tag to be the same as `next_unsigned_at`. This makes
				// sure only one transaction produced after `next_unsigned_at` will ever
				// get to the transaction pool and will end up in the block.
				// We can still have multiple transactions compete for the same "spot",
				// and the one with higher priority will replace other one in the pool.
				.and_provides(next_unsigned_at)
				// The transaction is only valid for next 5 blocks. After that it's
				// going to be revalidated by the pool.
				.longevity(5)
				// It's fine to propagate that transaction to other peers, which means it can be
				// created even by nodes that don't produce blocks.
				// Note that sometimes it's better to keep it for yourself (if you are the block
				// producer), since for instance in some schemes others may copy your solution and
				// claim a reward.
				.propagate(true)
				.build()
		}
	}
}

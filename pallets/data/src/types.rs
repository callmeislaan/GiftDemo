use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::inherent::Vec;
use scale_info::TypeInfo;
use serde::{Deserialize, Deserializer};

use crate::*;

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct ProofOfOnline<T: Config> {
	pub cluster_id: BoundedPeerString<T>,
	pub proof: u32,
}

#[derive(Clone, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[scale_info(skip_type_params(T))]
pub struct OnChainPeerInfo<T: Config> {
	pub cluster_id: BoundedPeerString<T>,
	pub cluster_public_address: Option<BoundedPeerString<T>>,
	pub ipfs_public_address: Option<BoundedPeerString<T>>,
	pub create_at: T::BlockNumber,
	pub provider: T::AccountId,
}

impl <T: Config> core::fmt::Debug for OnChainPeerInfo<T> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("OnChainPeerInfo")
		.field("cluster_id", &self.cluster_id)
		.field("cluster_public_address", &self.cluster_public_address)
		.field("ipfs_public_address", &self.ipfs_public_address)
		.field("created_at", &self.create_at)
		.field("provider", &self.provider)
		.finish()
	}
}

#[derive(Encode, Decode, Deserialize, Clone, TypeInfo, PartialEq, Eq)]
pub struct PeerInfoParameters {
	pub cluster_id: Vec<u8>,
	pub cluster_public_address: Option<Vec<u8>>,
	pub ipfs_public_address: Option<Vec<u8>>,
}

impl core::fmt::Debug for PeerInfoParameters {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("PeerInfoParameters")
		.field("cluster_id", &self.cluster_id)
		.field("cluster_public_address", &self.cluster_public_address)
		.field("ipfs_public_address", &self.ipfs_public_address)
		.finish()
	}
}
#[derive(Encode, Decode, Deserialize, Clone, TypeInfo, PartialEq, Eq)]
pub struct UpdatablePeerInfoParameters {
	pub cluster_public_address: Option<Vec<u8>>,
	pub ipfs_public_address: Option<Vec<u8>>,
}

impl core::fmt::Debug for UpdatablePeerInfoParameters {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("UpdatablePeerInfoParameters")
		.field("cluster_public_address", &self.cluster_public_address)
		.field("ipfs_public_address", &self.ipfs_public_address)
		.finish()
	}
}

#[derive(Encode, Decode, Debug, Deserialize, Clone)]
pub struct Peer {
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub id: Vec<u8>,
	#[serde(deserialize_with = "de_string_to_vec_bytes")]
	pub addresses: Vec<Vec<u8>>,
	#[serde(deserialize_with = "de_string_to_vec_bytes")]
	pub cluster_peers: Vec<Vec<u8>>,
	#[serde(deserialize_with = "de_string_to_vec_bytes")]
	pub cluster_peers_addresses: Vec<Vec<u8>>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub version: Vec<u8>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub commit: Vec<u8>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub rpc_protocol_version: Vec<u8>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub error: Vec<u8>,
	pub ipfs: Ipfs,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub peername: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Deserialize, Clone)]
pub struct CustomerString {
	#[serde(deserialize_with = "de_string_to_bytes")]
	value: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Deserialize, Clone)]
pub struct Ipfs {
	#[serde(deserialize_with = "de_string_to_bytes_option")]
	pub id: Option<Vec<u8>>,
	#[serde(deserialize_with = "de_string_to_vec_bytes")]
	pub addresses: Vec<Vec<u8>>,
	#[serde(deserialize_with = "de_string_to_bytes")]
	pub error: Vec<u8>,
}

pub fn de_string_to_bytes<'de, D>(de: D) -> Result<Vec<u8>, D::Error>
where
	D: Deserializer<'de>,
{
	let str_default = "";
	let s: &str = Deserialize::deserialize(de).unwrap_or(str_default);
	Ok(s.as_bytes().to_vec())
}

pub fn de_string_to_bytes_option<'de, D>(de: D) -> Result<Option<Vec<u8>>, D::Error>
where
	D: Deserializer<'de>,
{
	let str_default = "";
	let s: &str = Deserialize::deserialize(de).unwrap_or(str_default);
	Ok(Some(s.as_bytes().to_vec()))
}

pub fn de_string_to_vec_bytes<'de, D>(de: D) -> Result<Vec<Vec<u8>>, D::Error>
where
	D: Deserializer<'de>,
{
	let v: Vec<&str> = Deserialize::deserialize(de).unwrap_or(Vec::new());
	Ok(v.into_iter().map(|s| s.as_bytes().to_vec()).collect())
}

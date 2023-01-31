use codec::{Decode, Encode};
use frame_support::inherent::Vec;
use serde::{Deserialize, Deserializer};

#[derive(Encode, Decode, Debug, Deserialize)]
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

#[derive(Encode, Decode, Debug, Deserialize)]
pub struct CustomerString {
	#[serde(deserialize_with = "de_string_to_bytes")]
	value: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Deserialize)]
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
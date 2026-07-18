//! Serde adapters for the canonical DIG types the wire + persisted state speak.
//!
//! The core references peers and stores by the exact `Did` / `Bytes32` types dig-identity publishes
//! (never a hand-rolled string or 32-byte array), but those types are not themselves `serde`. These
//! adapters give them a stable, human-readable on-wire form — a `did:chia:` string for a DID and a
//! lowercase hex string for a 32-byte identifier — so a profile reference byte-agrees across
//! implementations.

/// A `Did` serialized as its canonical `did:chia:` string.
pub mod did_str {
    use dig_identity::Did;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a [`Did`] as its `did:chia:…` string form.
    pub fn serialize<S: Serializer>(did: &Did, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(did.as_str())
    }

    /// Parse a [`Did`] from its `did:chia:…` string form, rejecting anything malformed.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Did, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Did::parse(&raw).ok_or_else(|| serde::de::Error::custom("not a valid did:chia: string"))
    }
}

/// An `Option<Did>` serialized as an optional `did:chia:` string.
pub mod opt_did_str {
    use dig_identity::Did;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize an optional [`Did`], mapping `None` to a null.
    pub fn serialize<S: Serializer>(did: &Option<Did>, serializer: S) -> Result<S::Ok, S::Error> {
        match did {
            Some(did) => serializer.serialize_some(did.as_str()),
            None => serializer.serialize_none(),
        }
    }

    /// Parse an optional [`Did`], rejecting a present-but-malformed value.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Did>, D::Error> {
        let raw = Option::<String>::deserialize(deserializer)?;
        match raw {
            None => Ok(None),
            Some(raw) => Did::parse(&raw)
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom("not a valid did:chia: string")),
        }
    }
}

/// A `Bytes32` serialized as a lowercase 64-char hex string.
pub mod hex_bytes32 {
    use dig_identity::Bytes32;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a [`Bytes32`] as lowercase hex.
    pub fn serialize<S: Serializer>(bytes: &Bytes32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Parse a [`Bytes32`] from hex, rejecting a wrong length or non-hex input.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Bytes32, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let decoded = hex::decode(&raw).map_err(serde::de::Error::custom)?;
        let array: [u8; 32] = decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 32 bytes"))?;
        Ok(Bytes32::new(array))
    }
}

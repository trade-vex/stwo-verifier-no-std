use serde::{Serializer, Deserializer, Serialize, Deserialize};
use hex::{ToHex, FromHex, FromHexError};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// Module specifically for [u8; 32] arrays
pub mod hex_array_32 {
    use super::*;

    pub fn serialize<S>(array: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&array.encode_hex::<String>())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = Vec::<u8>::from_hex(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| {
            let msg = format!("Expected byte array of length 32, but got {}", bytes.len());
            serde::de::Error::custom(msg)
        })
    }
}

// Potentially add helpers for Vec<[u8; 32]>, Vec<Vec<[u8; 32]>> etc. if needed,
// although #[serde(with = "...")] on the field often handles nested structures correctly.
// If direct Vec<[u8;32]> serialization is needed:

// pub mod vec_hex_array_32 {
//     use super::*;

//     pub fn serialize<S>(vec_array: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let hex_strings: Vec<String> = vec_array.iter().map(|arr| arr.encode_hex::<String>()).collect();
//         hex_strings.serialize(serializer)
//     }

//     pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let hex_strings = Vec::<String>::deserialize(deserializer)?;
//         hex_strings.into_iter().map(|s| {
//             let bytes = Vec::<u8>::from_hex(&s).map_err(serde::de::Error::custom)?;
//              bytes.try_into().map_err(|_| {
//                 let msg = format!("Expected byte array of length 32, but got {}", bytes.len());
//                 serde::de::Error::custom(msg)
//             })
//         }).collect()
//     }
// } 
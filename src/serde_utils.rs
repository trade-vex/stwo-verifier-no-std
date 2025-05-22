use serde::{Serializer, Deserializer, Deserialize};
 // For Display
use alloc::fmt::Write; // For write_fmt
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format; // Added format macro import

// Helper function to encode bytes to hex string
fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        write!(&mut s, "{:02x}", byte).expect("Unable to write hex string");
    }
    s
}

// Helper function to decode hex string to bytes
fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}


pub fn serialize_hex<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[u8]>,
{
    // Use helper function
    serializer.serialize_str(&bytes_to_hex(data.as_ref()))
}

pub fn deserialize_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    // Use helper function
    hex_to_bytes(&s).map_err(serde::de::Error::custom)
}

pub fn deserialize_hex_array<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex_to_bytes(&s).map_err(serde::de::Error::custom)?;
    // Store length before move
    let bytes_len = bytes.len(); 
    bytes.try_into().map_err(|_|
        serde::de::Error::custom(format!(
            "Expected byte array of length {}, but got {}",
            N,
            bytes_len // Use stored length
        ))
    )
}

// Module specifically for [u8; 32] arrays
pub mod array_32 {
    use super::*; // Import helpers and serde types
    

    pub fn serialize<S>(array: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Use the generic serialize_hex helper
        serialize_hex(array, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        // Use the generic deserialize_hex_array helper
        deserialize_hex_array(deserializer)
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
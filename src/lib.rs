//! Decode and encode "type 3" reversible config passwords.
//!
//! Some network platforms store configured secrets not as one-way hashes but as
//! **reversible** ciphertext: a fixed 3DES key is compiled into the device's
//! firmware, and any secret marked as this format is encrypted under that key
//! and printed as lowercase hex. Because the key is the same on every unit,
//! anyone with the ciphertext can recover the cleartext — unless the operator
//! configured the optional user-supplied master key.
//!
//! Under the hood the cleartext is zero-padded to an 8-byte block boundary and
//! run through 3DES in CBC mode (no padding scheme of its own) using a 24-byte
//! key and an 8-byte IV equal to the low 8 bytes of that key.
//!
//! # Examples
//!
//! ```
//! use threedesco::{decode, encode, strip_trailing_zeros, TYPE3_IV, TYPE3_KEY};
//!
//! let ct = encode(b"example", &TYPE3_KEY, &TYPE3_IV);
//! assert_eq!(hex::encode(&ct), "d6ddbf2cfcc6be87");
//!
//! let pt = decode(&ct, &TYPE3_KEY, &TYPE3_IV).unwrap();
//! assert_eq!(strip_trailing_zeros(&pt), b"example");
//! ```

use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};

type Tdes3CbcDec = cbc::Decryptor<des::TdesEde3>;
type Tdes3CbcEnc = cbc::Encryptor<des::TdesEde3>;

/// The 24-byte 3DES key hardcoded in the target platform's crypto library.
/// Used for every reversible "type 3" value the device emits when no master
/// key has been configured. Recovered from firmware and verified:
/// `"example"` -> `d6ddbf2cfcc6be87`.
#[rustfmt::skip]
pub const TYPE3_KEY: [u8; 24] = [
    0x21, 0x0f, 0x60, 0x6f, 0x12, 0x6c, 0x57, 0xb7,
    0xab, 0x39, 0x6c, 0x8c, 0xde, 0x0a, 0x83, 0xa3,
    0x37, 0xb4, 0xdf, 0xbd, 0x1b, 0x44, 0xd3, 0x1d,
];

/// The 8-byte IV, equal to the low 8 bytes of [`TYPE3_KEY`] (== K3). The same
/// value is used for every device.
#[rustfmt::skip]
pub const TYPE3_IV: [u8; 8] = [
    0x37, 0xb4, 0xdf, 0xbd, 0x1b, 0x44, 0xd3, 0x1d,
];

/// Errors returned by [`decode`], [`parse_key`], and [`parse_iv`].
#[derive(Debug)]
pub enum Error {
    /// The input was not valid hexadecimal.
    Hex(hex::FromHexError),
    /// A key or IV hex string decoded to an unsupported byte length. `what` is
    /// `"key"` or `"IV"`; `got` is the number of bytes decoded.
    KeyIvLength {
        /// Which value was the wrong length (`"key"` or `"IV"`).
        what: &'static str,
        /// The number of bytes actually decoded.
        got: usize,
    },
    /// Ciphertext length was not a nonzero multiple of 8 bytes; holds the
    /// offending length.
    CiphertextLength(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Hex(e) => write!(f, "invalid hex: {e}"),
            Error::KeyIvLength { what, got } => {
                write!(f, "{what} must decode to a valid length (got {got} bytes)")
            }
            Error::CiphertextLength(n) => {
                write!(
                    f,
                    "ciphertext must be a nonzero multiple of 8 bytes (got {n})"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Hex(e) => Some(e),
            _ => None,
        }
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::Hex(e)
    }
}

/// Encode cleartext into a "type 3" ciphertext.
///
/// The cleartext is zero-padded up to an 8-byte block boundary (empty input
/// pads to one block) and encrypted with 3DES-CBC. The returned bytes are the
/// raw ciphertext; hex-encode them for the on-device representation.
///
/// # Panics
///
/// Panics only if the cipher backend rejects the key or IV. With the fixed
/// 24-byte key and 8-byte IV enforced by the type signature this cannot happen.
#[must_use]
pub fn encode(cleartext: &[u8], key: &[u8; 24], iv: &[u8; 8]) -> Vec<u8> {
    let mut buf = cleartext.to_vec();
    let padded_len = buf.len().div_ceil(8).max(1) * 8;
    buf.resize(padded_len, 0);

    let cipher =
        Tdes3CbcEnc::new_from_slices(key, iv).expect("24-byte key and 8-byte IV are valid");
    let ct = cipher
        .encrypt_padded::<NoPadding>(&mut buf, padded_len)
        .expect("buffer is block-aligned");
    ct.to_vec()
}

/// Decode a "type 3" ciphertext, returning the raw (still zero-padded)
/// plaintext bytes. Use [`strip_trailing_zeros`] to recover the cleartext.
///
/// # Errors
///
/// Returns [`Error::CiphertextLength`] if `ciphertext` is empty or its length
/// is not a multiple of 8 bytes.
///
/// # Panics
///
/// Panics only if the cipher backend rejects the key or IV. With the fixed
/// 24-byte key and 8-byte IV enforced by the type signature this cannot happen.
pub fn decode(ciphertext: &[u8], key: &[u8; 24], iv: &[u8; 8]) -> Result<Vec<u8>, Error> {
    if ciphertext.is_empty() || ciphertext.len() % 8 != 0 {
        return Err(Error::CiphertextLength(ciphertext.len()));
    }

    let mut buf = ciphertext.to_vec();
    let cipher =
        Tdes3CbcDec::new_from_slices(key, iv).expect("24-byte key and 8-byte IV are valid");
    let pt = cipher
        .decrypt_padded::<NoPadding>(&mut buf)
        .expect("ciphertext length is block-aligned");
    Ok(pt.to_vec())
}

/// Parse a 3DES key from a hex string.
///
/// Accepts a 24-byte key (48 hex chars) directly, or a 16-byte key (32 hex
/// chars) which is expanded to `K1|K2|K1` for 2-key 3DES. Surrounding
/// whitespace is trimmed.
///
/// # Errors
///
/// Returns [`Error::Hex`] if the string is not valid hex, or
/// [`Error::KeyIvLength`] if it does not decode to 16 or 24 bytes.
pub fn parse_key(hex_str: &str) -> Result<[u8; 24], Error> {
    let raw = hex::decode(hex_str.trim())?;
    match raw.len() {
        24 => {
            let mut key = [0u8; 24];
            key.copy_from_slice(&raw);
            Ok(key)
        }
        16 => {
            let mut key = [0u8; 24];
            key[0..16].copy_from_slice(&raw);
            key[16..24].copy_from_slice(&raw[0..8]);
            Ok(key)
        }
        n => Err(Error::KeyIvLength {
            what: "key",
            got: n,
        }),
    }
}

/// Parse an 8-byte IV from a hex string (16 hex chars). Surrounding whitespace
/// is trimmed.
///
/// # Errors
///
/// Returns [`Error::Hex`] if the string is not valid hex, or
/// [`Error::KeyIvLength`] if it does not decode to exactly 8 bytes.
pub fn parse_iv(hex_str: &str) -> Result<[u8; 8], Error> {
    let raw = hex::decode(hex_str.trim())?;
    if raw.len() != 8 {
        return Err(Error::KeyIvLength {
            what: "IV",
            got: raw.len(),
        });
    }
    let mut iv = [0u8; 8];
    iv.copy_from_slice(&raw);
    Ok(iv)
}

/// Return `data` with trailing zero bytes removed. The "type 3" scheme
/// zero-pads cleartext, so this recovers the original secret (unless the secret
/// itself ended in NUL bytes).
#[must_use]
pub fn strip_trailing_zeros(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    &data[..end]
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, parse_key, strip_trailing_zeros, TYPE3_IV, TYPE3_KEY};

    #[test]
    fn known_vectors_encode() {
        assert_eq!(
            hex::encode(encode(b"example", &TYPE3_KEY, &TYPE3_IV)),
            "d6ddbf2cfcc6be87"
        );
        assert_eq!(
            hex::encode(encode(b"secret", &TYPE3_KEY, &TYPE3_IV)),
            "bdb2c98561b8fa68"
        );
        assert_eq!(
            hex::encode(encode(b"openaccess", &TYPE3_KEY, &TYPE3_IV)),
            "ad16e21fea85ac63ee88c925de45fa28"
        );
    }

    #[test]
    fn known_vectors_decode() {
        let ct = hex::decode("d6ddbf2cfcc6be87").unwrap();
        let pt = decode(&ct, &TYPE3_KEY, &TYPE3_IV).unwrap();
        assert_eq!(strip_trailing_zeros(&pt), b"example");
    }

    #[test]
    fn round_trips() {
        for secret in [
            &b""[..],
            b"a",
            b"password1",
            b"longer secret spanning blocks!!",
        ] {
            let ct = encode(secret, &TYPE3_KEY, &TYPE3_IV);
            let pt = decode(&ct, &TYPE3_KEY, &TYPE3_IV).unwrap();
            assert_eq!(strip_trailing_zeros(&pt), secret);
        }
    }

    #[test]
    fn rejects_bad_ciphertext_length() {
        assert!(decode(b"", &TYPE3_KEY, &TYPE3_IV).is_err());
        assert!(decode(b"\x00\x01\x02", &TYPE3_KEY, &TYPE3_IV).is_err());
    }

    #[test]
    fn parse_key_expands_16_byte() {
        let k = parse_key("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(&k[0..8], &k[16..24]); // K3 == K1 for a 2-key key
        assert!(parse_key("zz").is_err());
        assert!(parse_key("00").is_err()); // 1 byte, unsupported length
    }
}

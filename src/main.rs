//! Simple tool to decode and encode "type 3" reversible config passwords.
//!
//! The target platform stores these values as lowercase hex. Under the hood
//! it calls OpenSSL's `DES_ede3_cbc_encrypt`: zero-pad the plaintext to an
//! 8-byte block boundary, encrypt under a hardcoded 24-byte 3DES key with a
//! hardcoded 8-byte IV (== K3), and emit the ciphertext as hex. Recoverable
//! only when the optional user-supplied master key was NOT configured on the
//! source device.

use std::process::exit;

use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use clap::Parser;

type Tdes3CbcDec = cbc::Decryptor<des::TdesEde3>;
type Tdes3CbcEnc = cbc::Encryptor<des::TdesEde3>;

/// The 24-byte 3DES key hardcoded in the target platform's crypto library.
/// Used for every reversible "type 3" value the device emits when no master
/// key has been configured. Recovered from firmware and verified:
/// "example" -> d6ddbf2cfcc6be87.
#[rustfmt::skip]
const TYPE3_KEY: [u8; 24] = [
    0x21, 0x0f, 0x60, 0x6f, 0x12, 0x6c, 0x57, 0xb7,
    0xab, 0x39, 0x6c, 0x8c, 0xde, 0x0a, 0x83, 0xa3,
    0x37, 0xb4, 0xdf, 0xbd, 0x1b, 0x44, 0xd3, 0x1d,
];

/// IV is the low 8 bytes of the key (== K3). Same value for every device.
#[rustfmt::skip]
const TYPE3_IV: [u8; 8] = [
    0x37, 0xb4, 0xdf, 0xbd, 0x1b, 0x44, 0xd3, 0x1d,
];

#[derive(Parser)]
#[command(
    name = "3desco",
    about = "Decode/encode \"type 3\" reversible config passwords",
    version
)]
struct Args {
    /// The value to operate on. When decoding (the default), this is the
    /// "type 3" ciphertext (hex, a multiple of 16 chars / 8 bytes). When
    /// encoding (--encode), this is the cleartext password.
    value: String,

    /// Encode instead of decode: treat VALUE as cleartext and emit the
    /// "type 3" ciphertext (lowercase hex).
    #[arg(short = 'e', long = "encode", default_value_t = false)]
    encode: bool,

    /// Override the 24-byte 3DES key (hex, 48 chars). If a 16-byte key is
    /// given (32 chars), it is expanded to K1|K2|K1 (2-key 3DES). Defaults to
    /// the baked-in key recovered from firmware.
    #[arg(long = "key3")]
    key3: Option<String>,

    /// Override the 8-byte IV (hex, 16 chars). Defaults to the baked-in
    /// IV (== low 8 bytes of the key).
    #[arg(long = "iv3")]
    iv3: Option<String>,

    /// Show the raw plaintext bytes when decoding, without stripping the
    /// trailing zero padding heuristically.
    #[arg(long = "raw", default_value_t = false)]
    raw: bool,
}

fn main() {
    let args = Args::parse();

    let key = resolve_key(args.key3.as_deref());
    let iv = resolve_iv(args.iv3.as_deref());

    if args.encode {
        type3_encode(&args.value, &key, iv);
    } else {
        type3_decode(&args.value, &key, iv, args.raw);
    }
}

/// Resolve the 24-byte 3DES key, defaulting to the baked-in constant.
fn resolve_key(key_hex: Option<&str>) -> [u8; 24] {
    match key_hex {
        None => TYPE3_KEY,
        Some(s) => {
            let raw = match hex::decode(s.trim()) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("[ERR] Invalid --key3 hex: {e}");
                    exit(-1);
                }
            };
            match raw.len() {
                24 => raw.as_slice().try_into().unwrap(),
                16 => {
                    let mut k = [0u8; 24];
                    k[0..16].copy_from_slice(&raw);
                    k[16..24].copy_from_slice(&raw[0..8]);
                    k
                }
                n => {
                    eprintln!("[ERR] --key3 must decode to 16 or 24 bytes (got {n}).");
                    exit(-1);
                }
            }
        }
    }
}

/// Resolve the 8-byte IV, defaulting to the baked-in constant.
fn resolve_iv(iv_hex: Option<&str>) -> [u8; 8] {
    match iv_hex {
        None => TYPE3_IV,
        Some(s) => {
            let raw = match hex::decode(s.trim()) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("[ERR] Invalid --iv3 hex: {e}");
                    exit(-1);
                }
            };
            if raw.len() != 8 {
                eprintln!("[ERR] --iv3 must decode to 8 bytes (got {}).", raw.len());
                exit(-1);
            }
            raw.as_slice().try_into().unwrap()
        }
    }
}

/// Decode a "type 3" password.
fn type3_decode(hex_str: &str, key: &[u8; 24], iv: [u8; 8], raw: bool) {
    let ct = match hex::decode(hex_str.trim()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[ERR] Invalid type 3 hex: {e}");
            exit(-1);
        }
    };
    if ct.is_empty() || ct.len() % 8 != 0 {
        eprintln!(
            "[ERR] type 3 ciphertext must be a nonzero multiple of 8 bytes (got {}).",
            ct.len()
        );
        exit(-1);
    }

    let mut buf = ct;
    let cipher = Tdes3CbcDec::new(key.as_slice().into(), (&iv).into());
    let Ok(pt) = cipher.decrypt_padded_mut::<NoPadding>(&mut buf) else {
        eprintln!("[ERR] Decryption failed (unexpected).");
        exit(-1);
    };
    let out = pt.to_vec();

    if raw {
        println!("[*] Raw plaintext bytes: {}", hex::encode(&out));
        println!("[*] As lossy UTF-8:      {}", String::from_utf8_lossy(&out));
        return;
    }

    let stripped = strip_trailing_zeros(&out);
    println!("[*] Result: {}", String::from_utf8_lossy(&stripped));
}

/// Encode a cleartext password into a "type 3" value.
fn type3_encode(cleartext: &str, key: &[u8; 24], iv: [u8; 8]) {
    // Zero-pad the plaintext up to an 8-byte block boundary, matching the
    // device's `DES_ede3_cbc_encrypt` call.
    let mut buf = cleartext.as_bytes().to_vec();
    let padded_len = buf.len().div_ceil(8).max(1) * 8;
    buf.resize(padded_len, 0);

    let cipher = Tdes3CbcEnc::new(key.as_slice().into(), (&iv).into());
    let Ok(ct) = cipher.encrypt_padded_mut::<NoPadding>(&mut buf, padded_len) else {
        eprintln!("[ERR] Encryption failed (unexpected).");
        exit(-1);
    };

    println!("[*] Result: {}", hex::encode(ct));
}

fn strip_trailing_zeros(data: &[u8]) -> Vec<u8> {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 0 {
        end -= 1;
    }
    data[..end].to_vec()
}

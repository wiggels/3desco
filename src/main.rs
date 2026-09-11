//! Command-line front end for the `threedesco` library: decode and encode
//! "type 3" reversible config passwords.

use std::process::exit;

use clap::Parser;

use threedesco::{decode, encode, parse_iv, parse_key, strip_trailing_zeros, TYPE3_IV, TYPE3_KEY};

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

    /// Show the raw plaintext bytes when decoding (hex line, then lossy UTF-8),
    /// without stripping the trailing zero padding heuristically.
    #[arg(long = "raw", default_value_t = false)]
    raw: bool,
}

/// Print an error to stderr and exit with a failure status.
fn fail(msg: &str) -> ! {
    eprintln!("[ERR] {msg}");
    exit(1);
}

fn main() {
    let args = Args::parse();

    let key = match args.key3.as_deref() {
        None => TYPE3_KEY,
        Some(s) => parse_key(s).unwrap_or_else(|e| fail(&format!("--key3: {e}"))),
    };
    let iv = match args.iv3.as_deref() {
        None => TYPE3_IV,
        Some(s) => parse_iv(s).unwrap_or_else(|e| fail(&format!("--iv3: {e}"))),
    };

    if args.encode {
        let ct = encode(args.value.as_bytes(), &key, &iv);
        println!("{}", hex::encode(ct));
    } else {
        let ciphertext = hex::decode(args.value.trim())
            .unwrap_or_else(|e| fail(&format!("invalid type 3 hex: {e}")));
        let plaintext = decode(&ciphertext, &key, &iv).unwrap_or_else(|e| fail(&e.to_string()));

        if args.raw {
            println!("{}", hex::encode(&plaintext));
            println!("{}", String::from_utf8_lossy(&plaintext));
        } else {
            println!(
                "{}",
                String::from_utf8_lossy(strip_trailing_zeros(&plaintext))
            );
        }
    }
}

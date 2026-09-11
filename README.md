# 3desco

A small command-line tool to decode and encode `"type 3"` reversible config
passwords.

Some network platforms store configured secrets not as one-way hashes but as
**reversible** ciphertext: a fixed 3DES key is compiled into the device's
firmware, and any secret marked as this format is simply encrypted under that
key and printed as hex. Because the key is the same on every unit and ships
inside the image, anyone with the ciphertext can recover the original
cleartext — unless the operator configured the optional user-supplied master
key, in which case these values are not recoverable with the baked-in key.

This tool implements that scheme in both directions.

## What it does

- **Decode** (default): take the stored hex value and recover the cleartext.
- **Encode**: take a cleartext string and produce the equivalent stored hex.

Under the hood: the cleartext is zero-padded to an 8-byte block boundary and
run through 3DES in CBC mode using the recovered 24-byte key and an 8-byte IV
(equal to the low 8 bytes of the key). Output is lowercase hex.

## Install

```sh
cargo build --release
# binary lands at target/release/3desco
```

To use it from anywhere, copy it onto your `PATH`:

```sh
cp target/release/3desco ~/.local/bin/    # or /usr/local/bin
```

> **macOS note:** the binary name starts with a digit. Running it straight out
> of the `target/` build directory can be killed by the OS; copy it to a normal
> `bin` location (as above) — or run it via `cargo run` — and it works fine.

## Docker

Prebuilt minimal images are published to the GitHub Container Registry on every
release. The image is a static binary in `scratch` (no shell, no OS), a few
megabytes in size, with `3desco` as its entrypoint:

```sh
# decode a stored value
docker run --rm ghcr.io/wiggels/3desco d6ddbf2cfcc6be87

# encode a cleartext string
docker run --rm ghcr.io/wiggels/3desco --encode example
```

Pin a specific version with a tag (`:0.1.0`, `:0.1`) or track `:latest`.

Build it yourself:

```sh
docker build -t 3desco .
docker run --rm 3desco --encode secret
```

## Usage

```
3desco [OPTIONS] <VALUE>
```

Decode a stored value (default mode):

```sh
$ 3desco d6ddbf2cfcc6be87
[*] Result: example
```

Encode a cleartext string:

```sh
$ 3desco --encode example
[*] Result: d6ddbf2cfcc6be87
```

The round trip is exact:

```sh
$ 3desco --encode secret
[*] Result: bdb2c98561b8fa68
$ 3desco bdb2c98561b8fa68
[*] Result: secret
```

Longer secrets span multiple blocks:

```sh
$ 3desco --encode openaccess
[*] Result: ad16e21fea85ac63ee88c925de45fa28
```

### Options

| Flag | Description |
|------|-------------|
| `-e`, `--encode` | Treat `VALUE` as cleartext and emit the ciphertext hex. Without this, `VALUE` is treated as ciphertext and decoded. |
| `--key3 <HEX>` | Override the 24-byte 3DES key (48 hex chars). A 16-byte key (32 hex chars) is expanded to `K1\|K2\|K1` (2-key 3DES). Defaults to the baked-in key. |
| `--iv3 <HEX>` | Override the 8-byte IV (16 hex chars). Defaults to the baked-in IV. |
| `--raw` | When decoding, show the raw plaintext bytes (hex + lossy UTF-8) without stripping trailing zero padding. Useful when the cleartext itself may contain trailing NULs. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version. |

The `--key3` / `--iv3` overrides let you point the same machinery at other
deployments or key material without rebuilding.

## Notes

- Ciphertext must be a nonzero multiple of 8 bytes (16 hex chars per block).
- Decoding strips trailing zero bytes by default, since the scheme zero-pads.
  Use `--raw` to see the untouched plaintext.
- If the source device had the optional master key configured, the stored value
  is **not** encrypted with the baked-in key and this tool cannot recover it.

## Legal

For authorized security testing, auditing of devices you own or administer, and
educational use only. You are responsible for complying with all applicable laws
and for having permission to recover any secret you run through it.

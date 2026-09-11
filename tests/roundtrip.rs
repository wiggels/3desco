//! End-to-end tests driving the built `3desco` binary, so CI exercises the
//! real CLI rather than internal helpers. Vectors are the ones documented in
//! the README, recovered and verified against the target firmware.

use std::process::Command;

/// Run the built binary with `args` and return the value printed after
/// `[*] Result: `.
fn run(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_3desco"))
        .args(args)
        .output()
        .expect("failed to spawn 3desco");
    assert!(
        out.status.success(),
        "3desco {args:?} exited with {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout not utf-8");
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("[*] Result: "))
        .unwrap_or_else(|| panic!("no result line in output: {stdout:?}"))
        .to_string()
}

#[test]
fn encodes_known_vectors() {
    assert_eq!(run(&["--encode", "example"]), "d6ddbf2cfcc6be87");
    assert_eq!(run(&["--encode", "secret"]), "bdb2c98561b8fa68");
    assert_eq!(
        run(&["--encode", "openaccess"]),
        "ad16e21fea85ac63ee88c925de45fa28"
    );
}

#[test]
fn decodes_known_vectors() {
    assert_eq!(run(&["d6ddbf2cfcc6be87"]), "example");
    assert_eq!(run(&["bdb2c98561b8fa68"]), "secret");
}

#[test]
fn round_trips() {
    for secret in ["a", "password1", "longer secret spanning blocks!!"] {
        let ct = run(&["--encode", secret]);
        assert_eq!(
            run(&[ct.as_str()]),
            secret,
            "round trip failed for {secret:?}"
        );
    }
}

#[test]
fn respects_key_and_iv_overrides() {
    // a non-default key must produce different ciphertext than the baked-in one
    let default = run(&["--encode", "example"]);
    let custom = run(&[
        "--encode",
        "example",
        "--key3",
        "00112233445566778899aabbccddeeff0011223344556677",
    ]);
    assert_ne!(default, custom);
    // and it must still round trip under that same key
    let back = run(&[
        custom.as_str(),
        "--key3",
        "00112233445566778899aabbccddeeff0011223344556677",
    ]);
    assert_eq!(back, "example");
}

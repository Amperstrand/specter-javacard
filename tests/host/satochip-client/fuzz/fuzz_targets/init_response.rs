#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the init_response parser: must error cleanly on any input,
    // never panic. Valid inputs exercise the full ECDH + KDF path.
    let sk_bytes: [u8; 32] = [0x42u8; 32];
    if let Ok(secret) = k256::SecretKey::from_slice(&sk_bytes) {
        let _ = satochip_client::channel::init_response(&secret, data);
    }
});

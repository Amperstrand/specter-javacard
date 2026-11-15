//! Farm conformance: prove the Rust client against a vpcd version-farm
//! member (or any pcscd SatoChip) — the same battery the python client
//! runs: version detect -> secure channel -> PIN -> derive + sign +
//! host-verify, N rounds.
//!
//!   cargo run --bin conformance -- --reader "jCardSim VPCD 00 01" --count 5

use std::time::Instant;

use satochip_client::client::{verify_signed, Client};

fn arg(name: &str) -> Option<String> {
    std::env::args().position(|a| a == name).and_then(|i| std::env::args().nth(i + 1))
}

fn main() {
    let reader = arg("--reader").unwrap_or_else(|| "jCardSim VPCD".into());
    let pin = arg("--pin").unwrap_or_else(|| "1234".into());
    let count: usize = arg("--count").and_then(|c| c.parse().ok()).unwrap_or(5);

    let t0 = Instant::now();
    let code = match run(&reader, &pin, count) {
        Ok(()) => {
            println!("CONFORMANCE OK ({:.1}s)", t0.elapsed().as_secs_f32());
            0
        }
        Err(e) => {
            eprintln!("CONFORMANCE FAILED: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run(reader: &str, pin: &str, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::connect(reader)?;
    client.select()?;
    println!("selected SatoChip on {reader:?}");

    let st = client.get_status()?;
    println!(
        "protocol {}.{} applet {}.{} pin0_tries={} seeded={} setup={}",
        st.protocol.0,
        st.protocol.1,
        st.applet.0,
        st.applet.1,
        st.pin0_tries,
        st.is_seeded,
        st.setup_done
    );

    client.init_secure_channel()?;
    println!("secure channel established");

    client.verify_pin(pin)?;
    println!("PIN verified");

    // m/84h/0h/0h/0/i
    let prefix: [u32; 4] = [84 + 0x8000_0000, 0x8000_0000, 0x8000_0000, 0];
    let mut verified = 0usize;
    for i in 0..count {
        let mut path = prefix.to_vec();
        path.push(i as u32);
        let (vk, chaincode) = client.get_extended_key(&path, true)?;
        let msg = format!("rust conformance {i}");
        let digest: [u8; 32] = sha2_digest(msg.as_bytes());
        let sig = client.sign_transaction_hash(&digest)?;
        verify_signed(&vk, &digest, &sig)?;
        println!(
            "  m/84h/0h/0h/0/{i}: {} sig verified (cc {}…)",
            &hex::encode(vk.to_encoded_point(true).as_bytes())[..16],
            &hex::encode(&chaincode)[..8],
        );
        verified += 1;
    }
    println!("{verified}/{count} sign+verify green");
    Ok(())
}

fn sha2_digest(msg: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(msg).into()
}

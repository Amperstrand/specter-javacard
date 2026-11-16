#![no_main]

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use libfuzzer_sys::fuzz_target;
use sha2::Digest;

fuzz_target!(|data: &[u8]| {
    let sk_bytes: [u8; 32] = [0x42u8; 32];
    if let Ok(secret) = k256::SecretKey::from_slice(&sk_bytes) {
        let card_sk =
            k256::ecdsa::SigningKey::from_slice(&[0x99u8; 32]).unwrap();
        let card_vk = k256::ecdsa::VerifyingKey::from(&card_sk);
        let card_pk = k256::PublicKey::from(&card_vk);
        let coordx = card_pk.to_encoded_point(false).x().unwrap().to_vec();
        let mut msg = Vec::new();
        msg.extend_from_slice(&(coordx.len() as u16).to_be_bytes());
        msg.extend_from_slice(&coordx);
        let digest: [u8; 32] = sha2::Sha256::digest(&msg).into();
        let (sig, _): (k256::ecdsa::Signature, _) =
            card_sk.sign_prehash(&digest).unwrap();
        let sig_der = sig.to_der().as_bytes().to_vec();
        let mut resp = Vec::new();
        resp.extend_from_slice(&(coordx.len() as u16).to_be_bytes());
        resp.extend_from_slice(&coordx);
        resp.extend_from_slice(&(sig_der.len() as u16).to_be_bytes());
        resp.extend_from_slice(&sig_der);

        if let Ok(ch) =
            satochip_client::channel::init_response(&secret, &resp)
        {
            let _ = ch.unwrap(data);
        }
    }
});

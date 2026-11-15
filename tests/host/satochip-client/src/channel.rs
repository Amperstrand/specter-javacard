//! SatoChip secure channel (INS 0x81 / 0x82) — identical across protocol
//! v0.14 and v0.16 (source-verified at both pinned tags).
//!
//! ECDH(host_ephemeral, card_ephemeral) -> shared x-coordinate;
//! session_key = HMAC-SHA160(x, b"sc_key")[0..16];
//! mac_key    = HMAC-SHA160(x, b"sc_mac")[0..20];
//! requests: iv(12 rand + u32-BE counter, last byte odd, counter += 2)
//!           || ct_len(2) || AES-128-CBC-PKCS7(inner) || 0x0014 || MAC20;
//! responses: iv(16) || ct_len(2) || ct.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, SecretKey};
use sha1::Sha1;

use crate::protocol::CLA;

type HmacSha1 = Hmac<Sha1>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub const MAC_LEN: usize = 20;

pub fn hmac_sha160(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Full INS 0x81 request APDU carrying our ephemeral public key.
pub fn init_request(secret: &SecretKey) -> Vec<u8> {
    let pub65 = secret.public_key().to_encoded_point(false);
    let mut apdu = vec![CLA, 0x81, 0x00, 0x00, pub65.len() as u8];
    apdu.extend_from_slice(pub65.as_bytes());
    apdu
}

/// Parse the 0x81 response and derive the session keys.
///
/// Response: [coordx_size(2) | coordx(32) | sig_size(2) | self-sig | ...].
/// The card's ephemeral public key is recovered from the self-signature
/// over sha256(0x0020 || coordx) — never assumed even-Y (the parity bug
/// class fixed everywhere else on this bench).
pub fn init_response(secret: &SecretKey, resp: &[u8]) -> Result<Channel, String> {
    if resp.len() < 4 {
        return Err(format!("init_response too short: {} bytes", resp.len()));
    }
    let coordx_size = u16::from_be_bytes([resp[0], resp[1]]) as usize;
    if coordx_size != 32 || resp.len() < 2 + coordx_size + 2 {
        return Err("bad coordx framing".into());
    }
    let coordx = &resp[2..2 + coordx_size];
    let sig_size = u16::from_be_bytes([resp[34], resp[35]]) as usize;
    if resp.len() < 36 + sig_size || sig_size == 0 {
        return Err("bad self-sig framing".into());
    }
    let sig_der = &resp[36..36 + sig_size];

    let card_vk = recover_coordx(coordx, sig_der)?;

    // shared x-coordinate = (secret * card_public).x
    let shared =
        ProjectivePoint::from(card_vk.as_affine()) * secret.to_nonzero_scalar().as_ref();
    let affine = shared.to_affine();
    let point = affine.to_encoded_point(false);
    let x_bytes: [u8; 32] = point
        .x()
        .ok_or("shared point x coordinate")?
        .as_slice()
        .try_into()
        .unwrap();

    let session_key = hmac_sha160(&x_bytes, b"sc_key");
    let mac_key = hmac_sha160(&x_bytes, b"sc_mac");
    let mut ch = Channel {
        session_key: [0u8; 16],
        mac_key: [0u8; MAC_LEN],
        counter: 1,
    };
    ch.session_key.copy_from_slice(&session_key[..16]);
    ch.mac_key.copy_from_slice(&mac_key[..MAC_LEN]);
    Ok(ch)
}

/// Recover the full public key from a coordx + DER self-signature over
/// sha256(0x0020 || coordx) — the INS 0x81 (secure channel) framing.
///
/// The card does NOT enforce low-S (bench-proven), so the signature is
/// normalized before recovery — exactly like the python client does.
pub fn recover_coordx(coordx: &[u8], sig_der: &[u8]) -> Result<PublicKey, String> {
    let mut msg = Vec::with_capacity(2 + coordx.len());
    msg.extend_from_slice(&(coordx.len() as u16).to_be_bytes());
    msg.extend_from_slice(coordx);
    recover_matching_x(&msg, coordx, sig_der)
}

/// Recover the extended-key public key from an INS 0x6D response.
///
/// The 0x6D self-signature covers sha256(chaincode || 0x0020 || coordx)
/// — 66 bytes, NOT the 0x81-style 34. Every earlier client missed this
/// and fell back to even-Y (~50% wrong pubkeys; the "missing self-sig"
/// note in the python parser was this framing difference, source-read
/// 2026-11-15 from the v0.14-0.2 getBIP32ExtendedKey signing block).
pub fn recover_xpub(
    chaincode: &[u8],
    coordx: &[u8],
    sig_der: &[u8],
) -> Result<PublicKey, String> {
    let mut msg = Vec::with_capacity(chaincode.len() + 2 + coordx.len());
    msg.extend_from_slice(chaincode);
    msg.extend_from_slice(&(coordx.len() as u16).to_be_bytes());
    msg.extend_from_slice(coordx);
    recover_matching_x(&msg, coordx, sig_der)
}

fn recover_matching_x(msg: &[u8], coordx: &[u8], sig_der: &[u8]) -> Result<PublicKey, String> {
    let sig = Signature::from_der(sig_der).map_err(|e| format!("self-sig DER: {e}"))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    for is_y_odd in [false, true] {
        for is_x_reduced in [false, true] {
            let rid = RecoveryId::new(is_y_odd, is_x_reduced);
            if let Ok(vk) = VerifyingKey::recover_from_msg(msg, &sig, rid) {
                let point = vk.to_encoded_point(false);
                if point.x().map(|x| x.as_slice() == coordx).unwrap_or(false) {
                    return Ok(vk.into());
                }
            }
        }
    }
    Err("pubkey recovery failed for coordx".into())
}

pub struct Channel {
    session_key: [u8; 16],
    mac_key: [u8; MAC_LEN],
    counter: u32,
}

impl Channel {
    /// Wrap an inner (plaintext) APDU into the full INS 0x82 request.
    pub fn wrap(&mut self, inner: &[u8], rng_bytes: &[u8; 12]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(rng_bytes);
        iv[12..].copy_from_slice(&self.counter.to_be_bytes());
        iv[15] |= 0x01;

        let ct = Aes128CbcEnc::new(&self.session_key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(inner);

        let mut mac_input = Vec::with_capacity(18 + ct.len());
        mac_input.extend_from_slice(&iv);
        mac_input.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        mac_input.extend_from_slice(&ct);
        let mac = hmac_sha160(&self.mac_key, &mac_input);

        let mut payload = Vec::with_capacity(20 + ct.len());
        payload.extend_from_slice(&iv);
        payload.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        payload.extend_from_slice(&ct);
        payload.extend_from_slice(&[0x00, MAC_LEN as u8]);
        payload.extend_from_slice(&mac);

        let mut apdu = vec![CLA, 0x82, 0x00, 0x00, payload.len() as u8];
        apdu.extend_from_slice(&payload);
        self.counter = self.counter.wrapping_add(2);
        apdu
    }

    /// Decrypt a response frame [iv(16) | ct_len(2) | ct].
    pub fn unwrap(&self, resp: &[u8]) -> Result<Vec<u8>, String> {
        if resp.len() < 18 {
            return Err("response frame too short".into());
        }
        let iv: [u8; 16] = resp[..16].try_into().unwrap();
        let ct_len = u16::from_be_bytes([resp[16], resp[17]]) as usize;
        if resp.len() < 18 + ct_len {
            return Err("response frame truncated".into());
        }
        let ct = &resp[18..18 + ct_len];
        Aes128CbcDec::new(&self.session_key.into(), &iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .map_err(|e| format!("decrypt/unpad: {e}"))
    }
}

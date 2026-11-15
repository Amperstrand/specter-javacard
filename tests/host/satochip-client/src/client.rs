//! SatoChip client over pcscd: plaintext ops, secure-channel ops, and the
//! semantics the contract pins (9C01 cache-reset retry, version-gated
//! factory reset, coordx+sig pubkey recovery).

use std::fs::File;
use std::io::Read;

use k256::ecdsa::VerifyingKey;
use k256::{PublicKey, SecretKey};

use crate::channel::{self, Channel};
use crate::protocol::{v014_02 as v14, v016_01 as v16, AID, CLA};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Status {
    pub protocol: (u8, u8),
    pub applet: (u8, u8),
    pub pin0_tries: u8,
    pub is_seeded: bool,
    pub setup_done: bool,
}

pub struct Client {
    card: pcsc::Card,
    channel: Option<Channel>,
    pub version: Option<(u8, u8)>,
}

fn rng(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("/dev/urandom");
    buf
}

impl Client {
    pub fn connect(reader_substr: &str) -> Result<Self> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let mut buf = [0; 4096];
        let mut readers = ctx.list_readers(&mut buf)?;
        let mut matching: Option<std::ffi::CString> = None;
        for r in &mut readers {
            if r.to_string_lossy().contains(reader_substr) {
                matching = Some(r.to_owned());
                break;
            }
        }
        let name = matching.ok_or_else(|| {
            format!("no pcscd reader matching {reader_substr:?}")
        })?;
        let card = ctx.connect(&name, pcsc::ShareMode::Shared, pcsc::Protocols::T1)?;
        Ok(Client { card, channel: None, version: None })
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut buf = [0u8; pcsc::MAX_BUFFER_SIZE];
        let rapdu = self.card.transmit(apdu, &mut buf)?;
        if rapdu.len() < 2 {
            return Err(format!("short response: {} bytes", rapdu.len()).into());
        }
        let n = rapdu.len() - 2;
        let sw = u16::from_be_bytes([rapdu[n], rapdu[n + 1]]);
        Ok((rapdu[..n].to_vec(), sw))
    }

    pub fn select(&mut self) -> Result<()> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, AID.len() as u8];
        apdu.extend_from_slice(&AID);
        let (_, sw) = self.transmit(&apdu)?;
        if sw != 0x9000 {
            return Err(format!("SELECT SatoChip: SW={sw:04X}").into());
        }
        Ok(())
    }

    pub fn get_status(&mut self) -> Result<Status> {
        let apdu = [CLA, v14::INS_GET_STATUS, 0x00, 0x00, 0x00];
        let (data, sw) = self.transmit(&apdu)?;
        if sw != 0x9000 || data.len() < 12 {
            return Err(format!("GET_STATUS: SW={sw:04X} len={}", data.len()).into());
        }
        self.version = Some((data[0], data[1]));
        Ok(Status {
            protocol: (data[0], data[1]),
            applet: (data[2], data[3]),
            pin0_tries: data[4],
            is_seeded: data[9] != 0,
            setup_done: data[10] != 0,
        })
    }

    pub fn init_secure_channel(&mut self) -> Result<()> {
        let sk_bytes: [u8; 32] = rng(32).try_into().unwrap();
        let secret = SecretKey::from_slice(&sk_bytes)?;
        let req = channel::init_request(&secret);
        let (data, sw) = self.transmit(&req)?;
        if sw != 0x9000 {
            return Err(format!("INIT_SC: SW={sw:04X}").into());
        }
        self.channel = Some(channel::init_response(&secret, &data)?);
        Ok(())
    }

    /// Wrap + send an inner APDU over the channel; one bounded re-init +
    /// retry on channel-class errors (9C20/21/22/23).
    pub fn secure_request(&mut self, inner: &[u8]) -> Result<Vec<u8>> {
        for attempt in 0..2 {
            let req = {
                let ch = self.channel.as_mut().ok_or("channel not open")?;
                ch.wrap(inner, &rng(12).try_into().unwrap())
            };
            let (data, sw) = self.transmit(&req)?;
            match sw {
                0x9000 => {
                    // no-output inner ops answer 9000 with empty data
                    if data.is_empty() {
                        return Ok(Vec::new());
                    }
                    let ch = self.channel.as_ref().ok_or("channel not open")?;
                    return ch.unwrap(&data).map_err(Into::into);
                }
                0x9C20 | 0x9C21 | 0x9C22 | 0x9C23 if attempt == 0 => {
                    self.init_secure_channel()?;
                }
                _ => return Err(format!("secure op: SW={sw:04X}").into()),
            }
        }
        unreachable!()
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        let p = pin.as_bytes();
        let mut inner = vec![CLA, v14::INS_VERIFY_PIN, 0x00, 0x00, p.len() as u8];
        inner.extend_from_slice(p);
        self.secure_request(&inner)?;
        Ok(())
    }

    /// Derive an extended key. Returns (recovered pubkey, chaincode).
    /// 9C01 (key cache full) retries with the P2 cache-reset bit (0x80).
    pub fn get_extended_key(
        &mut self,
        path: &[u32],
        for_signing: bool,
    ) -> Result<(VerifyingKey, Vec<u8>)> {
        let depth = path.len() as u8;
        let p2: u8 = if for_signing { 0x00 } else { 0x40 };
        let mut data = Vec::with_capacity(path.len() * 4);
        for lvl in path {
            data.extend_from_slice(&lvl.to_be_bytes());
        }
        let mk = |p2: u8| {
            let mut inner =
                vec![CLA, v14::INS_BIP32_GET_EXTENDED_KEY, depth, p2, data.len() as u8];
            inner.extend_from_slice(&data);
            inner
        };
        let resp = match self.secure_request(&mk(p2)) {
            Ok(r) => r,
            Err(e) if format!("{e}").contains("SW=9C01") => {
                self.secure_request(&mk(p2 | 0x80))?
            }
            Err(e) => return Err(e),
        };
        if resp.len() < 68 {
            return Err(format!("extended-key response too short: {}", resp.len()).into());
        }
        let chaincode = resp[..32].to_vec();
        let coordx = &resp[34..66];
        let sig_size = u16::from_be_bytes([resp[66], resp[67]]) as usize;
        let pk: PublicKey = if sig_size > 0 && resp.len() >= 68 + sig_size {
            channel::recover_xpub(&chaincode, coordx, &resp[68..68 + sig_size])?
        } else {
            // no self-sig (no-cache derivations on some builds): even-Y
            let mut sec1 = vec![0x02u8];
            sec1.extend_from_slice(coordx);
            PublicKey::from_sec1_bytes(&sec1)?
        };
        Ok((VerifyingKey::from(&pk), chaincode))
    }

    /// Sign a 32-byte digest with the last derived key (keynbr 0xFF);
    /// returns the DER signature.
    pub fn sign_transaction_hash(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let mut inner =
            vec![CLA, v14::INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00, digest.len() as u8];
        inner.extend_from_slice(digest);
        let sig = self.secure_request(&inner)?;
        if sig.is_empty() {
            return Err("empty signature".into());
        }
        Ok(sig)
    }

    /// v0.16-only single-APDU factory reset (0xFD, P1=0xAA P2=0x55).
    pub fn factory_reset(&mut self) -> Result<()> {
        let version = self.version_ok()?;
        if version < (0, 16) {
            return Err(format!(
                "factory_reset requires protocol 0.16; card is {}.{} \
                 (v0.14 reset = PIN+PUK exhaustion)",
                version.0, version.1
            )
            .into());
        }
        let inner = [CLA, v16::INS_RESET_TO_FACTORY_V3, 0xAA, 0x55, 0x00];
        self.secure_request(&inner)?;
        Ok(())
    }

    fn version_ok(&mut self) -> Result<(u8, u8)> {
        if self.version.is_none() {
            self.get_status()?;
        }
        Ok(self.version.unwrap())
    }
}

/// Host-side verification: the card signs the RAW 32-byte digest
/// (INS 0x7A input) — verify the DER sig against that digest directly.
/// S is normalized first (the card does not enforce low-S).
pub fn verify_signed(
    vk: &VerifyingKey,
    digest: &[u8; 32],
    sig_der: &[u8],
) -> Result<()> {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let sig = k256::ecdsa::Signature::from_der(sig_der)?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let prehash: k256::FieldBytes = (*digest).into();
    vk.verify_prehash(&prehash, &sig)?;
    Ok(())
}

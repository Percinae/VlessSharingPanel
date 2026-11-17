use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;

pub fn provisioning_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

fn totp_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC key");
    mac.update(&step.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 15) as usize;
    let value = u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    value % 1_000_000
}

pub fn verify_totp(secret: &[u8], code: &str) -> bool {
    if code.len() != 6 || !code.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Ok(code) = code.parse::<u32>() else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 30;
    [now.saturating_sub(1), now, now + 1]
        .iter()
        .any(|step| totp_at(secret, *step) == code)
}

#[cfg(test)]
pub fn current_code(secret: &[u8]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 30;
    format!("{:06}", totp_at(secret, now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_vector() {
        assert_eq!(totp_at(b"12345678901234567890", 59 / 30), 287082);
    }
}

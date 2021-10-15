//! One Time Password Support

use chrono::Utc;
use color_eyre::eyre;
use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;

/// Computes a new Hash-Based One-Time Password (HOTP) from a set of parameters
///
/// # Arguments
/// * `k` - shared secret between client and server; each HOTP generator has a different and unique secret K.
/// * `c` - 8-byte counter value, the moving factor. This counter MUST be synchronized between the HOTP generator (client) and the HOTP validator (server).
/// * `n` - number of digits in an HOTP value
pub fn hotp(k: impl AsRef<[u8]>, c: [u8; 8], n: u32) -> eyre::Result<u32> {
    // 1. generate HMAC-SHA-1(k, c)
    let mut mac = Hmac::<Sha1>::new_from_slice(k.as_ref()).expect("invalid key length");
    mac.update(&c);
    let mac = mac.finalize().into_bytes();

    // 2. Generate a 4-byte (32-bit) string (Dynamic Truncation)
    // NOTE: indexing here is safe as long as mac is HMAC-SHA-1.  The output is guaranteed to be
    // 20-bytes long and the masking it with 0xf (15) ensures there is enough runway (+3, max of
    // 18) so we don't read past the end of the array.
    let offset: usize = (mac[19] & 0xf).into();
    let bin_code: u32 = (((mac[offset] & 0x7f) as u32) << 24)
        | (((mac[offset + 1] & 0xff) as u32) << 16)
        | (((mac[offset + 2] & 0xff) as u32) << 8)
        | ((mac[offset + 3] & 0xff) as u32);

    // 3. Compute an HOTP value (mod N digits)
    let code = bin_code % (10_u32.pow(n));

    Ok(code)
}

/// Computes a new Time-Based One-Time Password (TOTP) form a set of parameters
///
/// # Arguments
/// * `k` - shared secret between client and server; each HOTP generator has a different and unique secret K.
/// * `step` - represents the time step in seconds
/// * `base` - Unix time to start counting time steps
/// * `n` - number of digits in an HOTP value
pub fn totp(k: impl AsRef<[u8]>, step: i64, base: i64, n: u32) -> eyre::Result<u32> {
    totp_internal(k, Utc::now().timestamp(), step, base, n)
}

/// Computes a new Time-Based One-Time Password (TOTP) form a set of parameters based on a set time
///
/// NOTE: this function is not exposed and is split from the main totp function to enable testing.
///
/// # Arguments
/// * `k` - shared secret between client and server; each HOTP generator has a different and unique secret K.
/// * `step` - represents the time step in seconds
/// * `base` - Unix time to start counting time steps
/// * `n` - number of digits in an HOTP value
#[inline(always)]
fn totp_internal(
    k: impl AsRef<[u8]>,
    time: i64,
    step: i64,
    base: i64,
    n: u32,
) -> eyre::Result<u32> {
    let t = (time - base) / step;
    hotp(k, t.to_be_bytes(), n)
}

#[cfg(test)]
mod tests {
    pub use super::*;

    const SECRET: &str = "12345678901234567890";

    #[test]
    fn hotp_count_0() {
        let counter: u64 = 0;
        let code = hotp(SECRET, counter.to_le_bytes(), 6).unwrap();
        assert_eq!(code, 755224);
    }

    #[test]
    fn hotp_count_1() {
        let counter: u64 = 1;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 287082);
    }

    #[test]
    fn hotp_count_2() {
        let counter: u64 = 2;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 359152);
    }

    #[test]
    fn hotp_count_3() {
        let counter: u64 = 3;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 969429);
    }

    #[test]
    fn hotp_count_4() {
        let counter: u64 = 4;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 338314);
    }

    #[test]
    fn hotp_count_5() {
        let counter: u64 = 5;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 254676);
    }

    #[test]
    fn hotp_count_6() {
        let counter: u64 = 6;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 287922);
    }

    #[test]
    fn hotp_count_7() {
        let counter: u64 = 7;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 162583);
    }

    #[test]
    fn hotp_count_8() {
        let counter: u64 = 8;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 399871);
    }

    #[test]
    fn hotp_count_9() {
        let counter: u64 = 9;
        let code = hotp(SECRET, counter.to_be_bytes(), 6).unwrap();
        assert_eq!(code, 520489);
    }

    #[test]
    fn totp_sha1_0() {
        let code = totp_internal(SECRET, 59, 30, 0, 8).unwrap();
        assert_eq!(code, 94287082);
    }

    #[test]
    fn totp_sha1_1() {
        let code = totp_internal(SECRET, 1111111109, 30, 0, 8).unwrap();
        assert_eq!(code, 07081804);
    }

    #[test]
    fn totp_sha1_2() {
        let code = totp_internal(SECRET, 1111111111, 30, 0, 8).unwrap();
        assert_eq!(code, 14050471);
    }

    #[test]
    fn totp_sha1_3() {
        let code = totp_internal(SECRET, 1234567890, 30, 0, 8).unwrap();
        assert_eq!(code, 89005924);
    }

    #[test]
    fn totp_sha1_4() {
        let code = totp_internal(SECRET, 2000000000, 30, 0, 8).unwrap();
        assert_eq!(code, 69279037);
    }

    #[test]
    fn totp_sha1_5() {
        let code = totp_internal(SECRET, 20000000000, 30, 0, 8).unwrap();
        assert_eq!(code, 65353130);
    }
}

// SPDX-License-Identifier: Apache-2.0

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{Error, Jitter, PhysHash};

type HmacSha256 = Hmac<Sha256>;

/// Compute jitter via HMAC-SHA256 with domain separation.
#[inline]
pub(crate) fn hmac_jitter(
    secret: &[u8; 32],
    inputs: &[u8],
    extra: &[u8],
    jmin: u32,
    range: u32,
) -> Jitter {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(b"cpop_jitter/v1/jitter");
    mac.update(inputs);
    mac.update(extra);
    let result = mac.finalize().into_bytes();
    let hash_val = u32::from_be_bytes([result[0], result[1], result[2], result[3]]);
    jmin.saturating_add(hash_val % range)
}

pub trait EntropySource {
    /// Collect entropy sample, binding hardware state to `inputs` context.
    fn sample(&self, inputs: &[u8]) -> Result<PhysHash, Error>;

    fn validate(&self, hash: PhysHash) -> bool;
}

/// Compute jitter delays from entropy. Must use constant-time ops on secrets.
pub trait JitterEngine {
    fn compute_jitter(&self, secret: &[u8; 32], inputs: &[u8], entropy: PhysHash) -> Jitter;
}

use sha1::{Digest as Sha1Digest, Sha1};

pub(crate) fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}

pub(crate) fn sha1_hex(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    // Canonical one-shot sha256→hex lives in hashkit; do not reimplement.
    hashkit::sha256_hash::sha256_hex(data)
}

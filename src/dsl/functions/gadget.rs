use crate::dsl::functions::encoding::hex_encode;

/// Build a minimal Java-serialization-shaped payload.
///
/// The format carries each string with a big-endian u16 length prefix, so a
/// segment longer than 65535 bytes cannot be represented. Truncating the
/// length while writing the full bytes would emit a malformed payload, so an
/// over-long segment is an error instead.
///
/// # Errors
/// Returns an error message when a segment exceeds the u16 length limit.
pub(crate) fn build_java_gadget_payload(
    gadget_type: &str,
    command: &str,
) -> Result<Vec<u8>, String> {
    let mut payload = vec![0xac, 0xed, 0x00, 0x05];
    for segment in [gadget_type, command] {
        let len = u16::try_from(segment.len()).map_err(|_| {
            format!(
                "java gadget segment is {} bytes; the serialization format caps segments at 65535",
                segment.len()
            )
        })?;
        payload.push(0x74);
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(segment.as_bytes());
    }
    Ok(payload)
}

pub(crate) fn encode_java_gadget_payload(payload: &[u8], encoding: &str) -> String {
    match encoding.to_ascii_lowercase().as_str() {
        "base64" | "b64" => encodex::base64::encode(payload),
        "hex" => hex_encode(payload),
        _ => String::from_utf8_lossy(payload).into_owned(),
    }
}

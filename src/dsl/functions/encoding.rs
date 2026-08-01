pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub(crate) fn url_encode(data: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut result = String::with_capacity(data.len());
    for b in data.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*b as char);
            }
            _ => {
                result.push('%');
                result.push(HEX[(b >> 4) as usize] as char);
                result.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    result
}

pub(crate) fn url_decode(data: &str) -> Result<String, ()> {
    let mut result = Vec::with_capacity(data.len());
    let bytes = data.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = hex_val(bytes[i + 1])?;
            let l = hex_val(bytes[i + 2])?;
            result.push((h << 4) | l);
            i += 3;
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(result).map_err(|_| ())
}

pub(crate) fn hex_decode(data: &str) -> Result<Vec<u8>, ()> {
    let bytes = data.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(());
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    encodex::base64::encode(bytes)
}

#[cfg(test)]
pub(crate) fn base64_decode(data: &str) -> Result<Vec<u8>, ()> {
    encodex::base64::decode(data).map_err(|_| ())
}

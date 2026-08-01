use guise_choice::random_item_with_rng;
use rand::{Rng, rngs::ThreadRng};

pub(crate) fn random_int(rng: &mut ThreadRng, min: i64, max: i64) -> i64 {
    if min >= max {
        return min;
    }

    rng.gen_range(min..max)
}

pub(crate) fn random_string(rng: &mut ThreadRng, len: usize, charset: &[u8]) -> String {
    let mut value = String::with_capacity(len);
    for _ in 0..len {
        let Some(byte) = random_item_with_rng(charset, rng) else {
            return value;
        };
        value.push(char::from(*byte));
    }
    value
}

#[cfg(test)]
mod tests {
    use super::random_string;

    #[test]
    fn random_string_empty_charset_returns_empty_without_panicking() {
        let mut rng = rand::thread_rng();
        assert_eq!(random_string(&mut rng, 16, b""), "");
    }

    #[test]
    fn random_string_preserves_byte_alphabet_promotion() {
        let mut rng = rand::thread_rng();
        let value = random_string(&mut rng, 16, &[0xff]);
        assert_eq!(value.chars().count(), 16);
        assert!(value.chars().all(|ch| ch == '\u{ff}'));
    }
}

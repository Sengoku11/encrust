pub struct AllegedRc4 {
    i: u8,
    j: u8,
    s: [u8; 256],
}

impl AllegedRc4 {
    // Key scheduling algorithm (KSA).
    // Once the vector s is initialized, the input key will not be used.
    pub fn new(k: &[u8]) -> Self {
        // NOTE: even though it's better to put some minimal length instead,
        // ARC4 is broken regardless the key length. In practice, you wouln't use it.
        assert!(!k.is_empty(), "ARC4 key cannot be empty");

        // Extend (repeat) the key if it's shorter than 256 bytes.
        let t: [u8; 256] = core::array::from_fn(|i| k[i % k.len()]);
        // Internal 256 bytes array that will be used instead of the key.
        let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(t[i]);
            s.swap(i, j as usize);
        }

        // Set i and j to zero.
        Self { i: 0, j: 0, s }
    }

    // Applies the ARC4 keystream on the given buffer in place.
    // Use for both to encode and decode.
    pub fn apply_keystream(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.process_byte(*b);
        }
    }

    // Generates one keystream byte and XORs it with the input.
    // Implements Pseudo-Random Generation Algorithm (PRGA).
    pub fn process_byte(&mut self, pb: u8) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);

        let i = self.i as usize;
        let j = self.j as usize;

        self.s.swap(i, j);

        let t = self.s[i].wrapping_add(self.s[j]);
        let k = self.s[t as usize];

        pb ^ k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"some not random key for tests";

    #[test]
    #[should_panic]
    fn test_empty_key_panic() {
        AllegedRc4::new(&[]);
    }

    #[test]
    fn test_oversized_key() {
        AllegedRc4::new(&[0u8; 500]);
    }

    #[test]
    fn test_encrypt() {
        let mut cipher = AllegedRc4::new(SEED);
        let mut decipher = AllegedRc4::new(SEED);

        let message = b"I want to encode this";
        let mut ciphertext = message.to_vec();

        cipher.apply_keystream(&mut ciphertext);
        assert_ne!(ciphertext, message, "Message should be encrypted");

        decipher.apply_keystream(&mut ciphertext);
        assert_eq!(ciphertext, message, "Message should be decrypted");
    }
}

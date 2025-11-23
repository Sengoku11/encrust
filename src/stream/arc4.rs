struct AllegedRc4 {
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
}

// use super::s_box::S;

#[derive(Debug)]
pub struct Aes {
    // rounds: u8,
    // round_keys: [u128; 15],
}

impl Aes {
    /// Creates an `Aes` instance from a `key` split into 32-bit chunks.
    /// The effective key size must be 128, 192 or 256 bits.
    pub fn new(key: [u32; 8]) -> Result<Self, &'static str> {
        // Get the index of where the effective key starts.
        let head = match key.iter().position(|&v| v != 0) {
            Some(id) => id,
            None => return Err("key cannot be empty"),
        };

        if !matches!(head, 0 | 2 | 4) {
            return Err("key size must be 128, 192 or 256 bits");
        };

        let keys_len = 8 - head; // number of 32-bit chunks in 128/192/256-bit key
        let rounds = 14 - head; // number of rounds
        let words_in_key = 4; // amount of 32-bit words in a 128-bit block
        let words_len = words_in_key * (rounds + 1); // number of words in expanded 128-bit keys

        // Up to 16 leading words can be 0s if the `head` != 0.
        let mut words: [u32; 4 * 15] = [0u32; 4 * 15];
        let words_head = words.len() - words_len;

        // TODO: how to test this indexing stuff:
        // result should be the same when using arrays (and key) of smaller size
        // meanwhile trust it works and focus on implementing smaller functions
        for i in words_head..words.len() {
            // To mitigate leading zeros we use a second index
            let j = i - words_head; // j always begins with zero

            if j < 8 {
                words[i] = key[j]; // seed with original key
            } else {
                // expand words
                let temp = words[i - 1];

                if j.is_multiple_of(keys_len) {
                    // 1. Rotate left auth Auth
                    // 2. Apply s_box
                    // 3. Expand with the rcon table: Rcon[i / keys_len]
                } else if (keys_len > 6) && (j % keys_len == 4) {
                    // apply s_box
                }

                words[i] = temp ^ words[i - keys_len];
            }
        }

        // combine words into 128 bit round keys

        Ok(Self {
            // rounds: 14 - head as u8,
            // round_keys: [0u128; 15],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ksa() {
        #[rustfmt::skip]
        let key: [u32; 8] = [
            2430607645, 2477337209, 3966267802, 2832764579, 
            4025463770, 2937464051, 2278884081, 3015632120,
        ];

        Aes::new(key).expect("Aes::new failed for this key");
    }

    #[test]
    // #[should_panic(expected = "key size must be 128, 192 or 256 bits")]
    fn test_ksa_panic() {
        #[rustfmt::skip]
        let key: [u32; 8] = [
                     0, 2477337209, 3966267802, 2832764579, 
            4025463770, 2937464051, 2278884081, 3015632120,
        ];

        Aes::new(key).expect_err("key size must be 128, 192 or 256 bits");
    }
}

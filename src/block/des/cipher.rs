use super::permutation_tables::{E, FINAL_PERMUTATION, INITIAL_PERMUTATION, P, PC_1, PC_2};
use super::s_boxes::S;

/// Data Encryption Standard
pub struct Des {
    round_keys: [u64; 16],
}

/// 0b00000000_00000000_00000000_00000000_00001111_11111111_11111111_11111111;
const MASK_RIGHT_28_BIT: u64 = (1u64 << 28) - 1;
/// 0b00000000_11111111_11111111_11111111_11110000_00000000_00000000_00000000;
const MASK_LEFT_28_BIT: u64 = ((1u64 << 56) - 1) ^ MASK_RIGHT_28_BIT;

/// 0b00000000_00000000_00000000_00000000_11111111_11111111_11111111_11111111;
const MASK_RIGHT_32_BIT: u64 = (1u64 << 32) - 1;
/// 0b11111111_11111111_11111111_11111111_00000000_00000000_00000000_00000000;
const MASK_LEFT_32_BIT: u64 = u64::MAX ^ MASK_RIGHT_32_BIT;

impl Des {
    /// Implements Key Scheduling Algorithm (KSA).
    pub fn new(k: u64) -> Self {
        // PC-1 step. Permutate and reduce original key.
        let mut key_56_bit: u64 = permutate(k, &PC_1, 64);

        // Key rotation step. Generate 16 56-bits keys.
        let precompressed_keys: [u64; 16] = core::array::from_fn(|i| {
            key_56_bit = rotate_key(key_56_bit, i);
            key_56_bit
        });

        // PC-2 step. Compress into 48-bit keys.
        let round_keys = core::array::from_fn(|i| permutate(precompressed_keys[i], &PC_2, 56));

        Self { round_keys }
    }

    /// Encrypt any given 64-bit block of text.
    pub fn encrypt(&self, plain_block: u64) -> u64 {
        let ip_block: u64 = permutate(plain_block, &INITIAL_PERMUTATION, 64);

        let mut left: u64 = (ip_block & MASK_LEFT_32_BIT) >> 32;
        let mut right: u64 = ip_block & MASK_RIGHT_32_BIT;

        // Twist halves and apply f function.
        for i in 0..16 {
            (left, right) = (right, left ^ apply_f(right, self.round_keys[i]));
        }

        (left, right) = (right, left);

        let merged = merge_halves(left, right, 32);

        permutate(merged, &FINAL_PERMUTATION, 64)
    }

    /// Encrypt any given 64-bit block of text.
    pub fn decrypt(&self, cipher_block: u64) -> u64 {
        let ip_block: u64 = permutate(cipher_block, &INITIAL_PERMUTATION, 64);

        let mut left: u64 = (ip_block & MASK_LEFT_32_BIT) >> 32;
        let mut right: u64 = ip_block & MASK_RIGHT_32_BIT;

        // Twist halves and apply f function.
        for i in (0..=15).rev() {
            (left, right) = (right, left ^ apply_f(right, self.round_keys[i]));
        }

        (left, right) = (right, left);

        let merged = merge_halves(left, right, 32);

        permutate(merged, &FINAL_PERMUTATION, 64)
    }
}

/// Applies the DES round function f to a 32-bit half-block
/// using the given round key.
/// TODO: test
fn apply_f(right: u64, round_key: u64) -> u64 {
    // Expand 32-bit half-block into 48 bits.
    let expanded: u64 = permutate(right, &E, 32);

    // Mix with the round key.
    let keyed: u64 = expanded ^ round_key;

    // Split encrypted block into eight 6-bit chunks.
    let mut chunks: [u64; 8] = split_6bit_chunks(keyed);

    // Substitute each chunk with its 4-bits S-box output.
    for (i, s_box) in S.iter().enumerate() {
        chunks[i] = substitute(chunks[i], s_box);
    }

    let merged_32bit: u64 = merge_4bit_chunks(chunks);

    // Permutate with P to produce the final 32-bit output.
    permutate(merged_32bit, &P, 32)
}

/// Takes bits from the input key `k` at positions specified in permutation vector,
/// and writes them sequentially into the output key.
fn permutate(k: u64, permutation_vec: &[u8], k_size: u8) -> u64 {
    if k_size < 64 {
        assert!(k < (1u64 << k_size), "k is bigger than declared k_size");
    }

    let mut result: u64 = 0;

    // Lookup an input bit and "push" it to the result number.
    for bit_pos in permutation_vec.iter() {
        let shift = (k_size - bit_pos) as u64;
        let input_bit = (k >> shift) & 1;
        result = (result << 1) | input_bit;
    }

    result
}

/// Rotates 56-bit key `k` by one or two positions depending on the round `r`.
fn rotate_key(k: u64, r: usize) -> u64 {
    assert!(r < 16, "max round is 15 (counting from round0)");
    let rotations = if matches!(r, 0 | 1 | 8 | 15) { 1 } else { 2 };

    // Split key and rotate its parts.
    let left: u64 = rotate_left((k & MASK_LEFT_28_BIT) >> 28, rotations);
    let right: u64 = rotate_left(k & MASK_RIGHT_28_BIT, rotations);

    // Merge back into 56-bit key.
    merge_halves(left, right, 28)
}

/// Rotates left 28-bit value `n` times.
fn rotate_left(k: u64, n: usize) -> u64 {
    assert!(k < (1u64 << 28), "key must fit in 28 bits");

    let mut result = k;

    for _ in 0..n {
        let leading_bit = (result >> 27) & 1;
        let shifted = (result << 1) & MASK_RIGHT_28_BIT;

        result = shifted | leading_bit;
    }
    result
}

/// For a given 6-bit `chunk` returns a 4-bit output from the `s_box`.
fn substitute(chunk: u64, s_box: &[u8; 64]) -> u64 {
    let row = ((chunk >> 4) & 0b10) | (chunk & 1);
    let col = (chunk & 0b11111) >> 1;
    s_box[(16 * row + col) as usize] as u64
}

/// Splits 48-bit value into eight 6-bit chunks.
fn split_6bit_chunks(block: u64) -> [u64; 8] {
    core::array::from_fn(|i| (block >> (48 - (i + 1) * 6)) & 0b111111)
}

/// Merges 4-bit chunks into one 32-bit value.
fn merge_4bit_chunks(chunks: [u64; 8]) -> u64 {
    let mut result: u64 = 0;
    for chunk in chunks {
        result <<= 4;
        result |= chunk;
    }
    result
}

/// Takes two parts (each <= 32-bit) and merge them into one double `half_size` bit value.
fn merge_halves(left: u64, right: u64, half_size: usize) -> u64 {
    assert!(half_size <= 32, "half_size cannot be bigger than 32 bits");
    let limit = 1u64 << half_size;
    assert!(
        left < limit && right < limit,
        "left or right half do not fit into {} bits",
        half_size
    );

    let mut merged: u64 = 0;

    for i in 0..half_size {
        merged = (merged << 1) | ((left >> (half_size - i - 1)) & 1);
    }
    for i in 0..half_size {
        merged = (merged << 1) | ((right >> (half_size - i - 1)) & 1);
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let cipher = Des::new(u64::MAX - 1234);

        let plaintext: u64 = 123456789101112u64;
        let ciphertext: u64 = cipher.encrypt(plaintext);

        assert_ne!(plaintext, ciphertext);
        assert_eq!(plaintext, cipher.decrypt(ciphertext));

        // TODO: more tests:
        // 1. output is different with different key
        // 2. output is different with different plaintext
        // 3. output is always the same with same inputs
    }

    #[test]
    #[should_panic(expected = "k is bigger than declared k_size")]
    fn test_permutate_panic() {
        permutate(u64::MAX, &PC_1, 56);
    }

    #[test]
    fn test_pc_1() {
        let key: u64 = 18446744073709550381;
        // 11111111_11111111_11111111_11111111_11111111_11111111_11111011_00101101
        let expected = 35888057248645119;
        // 00000000_01111111_01111111_11111111_01110111_11111011_11111111_11111111
        assert_eq!(permutate(key, &PC_1, 64), expected);
    }

    #[test]
    fn test_pc_2() {
        let key: u64 = 35888057248645119;
        // 00000000_01111111_01111111_11111111_01110111_11111011_11111111_11111111
        let expected = 272678883688445;
        // 00000000_00000000_11110111_11111111_11111111_11111111_11111111_11111101;
        assert_eq!(permutate(key, &PC_2, 56), expected);
    }

    #[test]
    fn test_rotate_left_28_bit() {
        let key = 216433336u64;
        // 1100111001101000001010111000
        let rotations = 2;
        let expected = 60426979u64;
        // 0011100110100000101011100011
        assert_eq!(rotate_left(key, rotations), expected);
    }

    #[test]
    fn test_rotate_left_24_bit() {
        let key = 16433336u64; // key is 24-bit now
        // 0000111110101100000010111000
        let rotations = 1;
        let expected = 32866672u64;
        // 0001111101011000000101110000
        assert_eq!(rotate_left(key, rotations), expected);
    }

    #[test]
    fn test_rotate_key() {
        let key: u64 = 46842079712850309;
        let round = 3; // two rotations
        // 1010011001101010100111111001_0001110100110011000110000101
        let expected: u64 = 43253131312416276;
        // 1001100110101010011111100110_0111010011001100011000010100
        assert_eq!(rotate_key(key, round), expected);
    }

    #[test]
    fn test_substitution() {
        assert_eq!(substitute(0b011011, &S[4]), 9, "s_box test 1");
        assert_eq!(substitute(0b111110, &S[0]), 0, "s_box test 2");
        assert_eq!(substitute(0b111011, &S[2]), 5, "s_box test 3");
    }

    #[test]
    fn test_merge_halves() {
        assert_eq!(merge_halves(0b10_1010, 0b01_1111, 6), 0b1010_1001_1111);
        assert_eq!(
            merge_halves(
                0b1111_0000_1111_0000_1111_0000_1111,
                0b0000_1111_0000_1111_0000_1111_0000,
                28
            ),
            0b1111_0000_1111_0000_1111_0000_1111_0000_1111_0000_1111_0000_1111_0000
        );
        assert_eq!(
            merge_halves(0xDEAD_BEEF, 0x0123_4567, 32),
            0xDEAD_BEEF_0123_4567
        );
        assert_eq!(merge_halves(0, 0, 6), 0b000000_000000);
        assert_eq!(merge_halves(0, 0b111111, 6), 0b000000_111111);
        assert_eq!(merge_halves(0b1, 0b0, 1), 0b10);
        assert_eq!(merge_halves(0b1010, 0b0101, 4), 0b1010_0101);
        assert_eq!(merge_halves(0xFFFF_FFFF, 0, 32), 0xFFFF_FFFF_0000_0000);
    }

    #[test]
    fn test_split_6bit_chunks() {
        let output = split_6bit_chunks(0b111101_101110_011110_011001_101100_010101_001111_010100);
        let expected: [u64; 8] = [
            0b111101, 0b101110, 0b011110, 0b011001, 0b101100, 0b010101, 0b001111, 0b010100,
        ];
        assert_eq!(output, expected);
    }

    #[test]
    fn test_merge_4bit_chunks() {
        let output = merge_4bit_chunks([
            0b1111, 0b1011, 0b0111, 0b0110, 0b1011, 0b0101, 0b0011, 0b0101,
        ]);
        let expected: u64 = 0b11111011011101101011010100110101;
        assert_eq!(output, expected);
    }
}

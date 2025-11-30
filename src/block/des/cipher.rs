use super::permutation_tables::{PC_1, PC_2};

/// Data Encryption Standard
pub struct Des {
    round_keys: [u64; 16],
}

/// 0b00000000_00000000_00000000_00000000_00001111_11111111_11111111_11111111;
const MASK_RIGHT_28_BIT: u64 = (1u64 << 28) - 1;
/// 0b00000000_11111111_11111111_11111111_11110000_00000000_00000000_00000000;
const MASK_LEFT_28_BIT: u64 = ((1u64 << 56) - 1) ^ MASK_RIGHT_28_BIT;

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

    // Merge parts back.
    let mut res: u64 = 0;
    for i in 0..28 {
        res = (res << 1) | ((left >> (27 - i)) & 1);
    }
    for i in 0..28 {
        res = (res << 1) | ((right >> (27 - i)) & 1);
    }

    res
}

/// Rotate left n times but keeps size of 28-bit.
fn rotate_left(k: u64, n: usize) -> u64 {
    assert!(k < (1u64 << 28), "key must fit in 28 bits");
    let mut result = k;
    for _ in 0..n {
        result = rotate_left_once(result);
    }
    result
}

/// Rotate left within 28-bit.
fn rotate_left_once(k: u64) -> u64 {
    let leading_bit = (k >> 27) & 1;
    let shifted = (k << 1) & MASK_RIGHT_28_BIT;

    shifted | leading_bit
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_scheduling() {
        Des::new(u64::MAX - 1234);
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
}

/// This table specifies the input permutation on a 64-bit block.
///
/// The first bit of the output is taken from the 58th bit of the input;
/// the second bit from the 50th bit, and so on, with the last bit of the
/// output taken from the 7th bit of the input.
const INITIAL_PERMUTATION: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, // 2, 4, ...
    60, 52, 44, 36, 28, 20, 12, 4, //
    62, 54, 46, 38, 30, 22, 14, 6, //
    64, 56, 48, 40, 32, 24, 16, 8, //
    // odds and even split
    57, 49, 41, 33, 25, 17, 9, 1, // 1, 3, ...
    59, 51, 43, 35, 27, 19, 11, 3, //
    61, 53, 45, 37, 29, 21, 13, 5, //
    63, 55, 47, 39, 31, 23, 15, 7, //
];

/// Inverse of the INITIAL_PERMUTATION.
const FINAL_PERMUTATION: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, //
    39, 7, 47, 15, 55, 23, 63, 31, //
    38, 6, 46, 14, 54, 22, 62, 30, //
    37, 5, 45, 13, 53, 21, 61, 29, //
    36, 4, 44, 12, 52, 20, 60, 28, //
    35, 3, 43, 11, 51, 19, 59, 27, //
    34, 2, 42, 10, 50, 18, 58, 26, //
    33, 1, 41, 9, 49, 17, 57, 25, //
];

/* PC_1 Visualization
 *         Left                     Right    Parity Bits
 * row 1: 57  58  59  60     | 61  62  63 |  64
 * row 2: 49  50  51  52     | 53  54  55 |  56
 * row 3: 41  42  43  44     | 45  46  47 |  48
 * row 4: 33  34  35  36   __| 37  38  39 |  40
 * row 5: 25  26  27     | 28  29  30  31 |  32
 * row 6: 17  18  19     | 20  21  22  23 |  24
 * row 7:  9  10  11     | 12  13  14  15 |  16
 * row 8:  1   2   3     |  4   5   6   7 |   8
 */

/// Permutated Choice 1
const PC_1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, //
    1, 58, 50, 42, 34, 26, 18, //
    10, 2, 59, 51, 43, 35, 27, //
    19, 11, 3, 60, 52, 44, 36, //
    63, 55, 47, 39, 31, 23, 15, //
    7, 62, 54, 46, 38, 30, 22, //
    14, 6, 61, 53, 45, 37, 29, //
    21, 13, 5, 28, 20, 12, 4, //
];

/// Key Compression Table
const PC_2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, //
    15, 6, 21, 10, 23, 19, 12, 4, //
    26, 8, 16, 7, 27, 20, 13, 2, //
    41, 52, 31, 37, 47, 55, 30, 40, //
    51, 45, 33, 48, 44, 49, 39, 56, //
    34, 53, 46, 42, 50, 36, 29, 32,
];

/// 0b00000000_00000000_00000000_00000000_00001111_11111111_11111111_11111111;
const MASK_RIGHT_28_BIT: u64 = (1u64 << 28) - 1;
/// 0b00000000_11111111_11111111_11111111_11110000_00000000_00000000_00000000;
const MASK_LEFT_28_BIT: u64 = ((1u64 << 56) - 1) ^ MASK_RIGHT_28_BIT;

/// Data Encryption Standard
pub struct Des {
    round_keys: [u64; 16],
}

impl Des {
    /// Implements Key Scheduling Algorithm (KSA).
    pub fn new(k: u64) -> Self {
        let mut state: u64 = permutate(k, &PC_1);

        let precompressed_keys: [u64; 16] = core::array::from_fn(|i| {
            state = rotate_key(state, i);
            state
        });

        let round_keys = core::array::from_fn(|i| permutate(precompressed_keys[i], &PC_2));

        Self { round_keys }
    }
}

/// Takes bits from the input key `k` at positions specified in permutation vector,
/// and writes them sequentially into the output key.
fn permutate(k: u64, permutation_vec: &[u8]) -> u64 {
    let mut result: u64 = 0;

    for bit_pos in permutation_vec.iter() {
        let shift = (64 - bit_pos) as u64;
        let input_bit = (k >> shift) & 1;
        result = (result << 1) | input_bit;
    }

    result
}

/// Rotates 56-bit key `k` by one or two positions depending on the round `r`.
fn rotate_key(k: u64, r: usize) -> u64 {
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
    fn test_permutation_tables() {
        // TODO: test other tables
        for (i, &n) in INITIAL_PERMUTATION.iter().enumerate() {
            assert_eq!((i + 1) as u8, FINAL_PERMUTATION[(n - 1) as usize]);
        }
    }

    #[test]
    fn test_pc_1() {
        let key: u64 = 18446744073709550381;
        // 11111111_11111111_11111111_11111111_11111111_11111111_11111011_00101101
        let expected = 35888057248645119;
        // 00000000_01111111_01111111_11111111_01110111_11111011_11111111_11111111
        assert_eq!(permutate(key, &PC_1), expected);
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

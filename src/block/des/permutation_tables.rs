/// This table specifies the input permutation on a 64-bit block.
///
/// The first bit of the output is taken from the 58th bit of the input;
/// the second bit from the 50th bit, and so on, with the last bit of the
/// output taken from the 7th bit of the input.
pub(super) const INITIAL_PERMUTATION: [u8; 64] = [
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
pub(super) const FINAL_PERMUTATION: [u8; 64] = [
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
pub(super) const PC_1: [u8; 56] = [
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
pub(super) const PC_2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, //
    15, 6, 21, 10, 23, 19, 12, 4, //
    26, 8, 16, 7, 27, 20, 13, 2, //
    41, 52, 31, 37, 47, 55, 30, 40, //
    51, 45, 33, 48, 44, 49, 39, 56, //
    34, 53, 46, 42, 50, 36, 29, 32,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permutation_tables() {
        // TODO: test other tables
        for (i, &n) in INITIAL_PERMUTATION.iter().enumerate() {
            assert_eq!((i + 1) as u8, FINAL_PERMUTATION[(n - 1) as usize]);
        }

        // Weak guard, but still better than nothing.
        for (i, &n) in PC_2.iter().enumerate() {
            if i < 24 {
                assert!(n <= 28)
            } else {
                assert!(n > 28)
            };
        }
    }
}

pub const xe5_len: [u8; 10] = [16 , 16 , 17 , 31 , 19 , 29 , 23 , 25 , 27 , 37];

// {
// int i , j , l ;
// uint64_t x , t , ri [10];
// for ( i = 0; i < 10; i ++)
// ri [ i ] = 0;
// // initialize
// for ( i = 3; i >= 0; i - -) {
// // four words
// x = d [ i ];
// // payload
// for ( j = 1; j < 10; j ++) {
// l = xe5_len [ j ];
// // length
// t = ( ri [ j ] << (64 % l ) ) ;
// // rotate
// t ^= x ;
// // payload
// if ( l < 32)
// // extra fold
// t ^= t >> (2 * l ) ;
// t ^= t >> l ;
// // fold
// ri [ j ] = t & ((1 llu << l ) - 1) ; // mask
// }
// x ^= x >> 8;
// // parity of 16
// x ^= x >> 4;
// x ^= x >> 2;
// x ^= x >> 1;
// x &= 0 x 0 0 0 1 0 0 0 1 0 0 0 1 0 0 0 1 ;
// // four parallel
// x ^= ( x >> (16 - 1) ) ^ ( x >> (32 - 2) ) ^ ( x >> (48 - 3) ) ;
// ri [0] |= ( x & 0 xF ) << (4 * i ) ;
// }
// // pack coefficients into 240 bits ( note output the XOR )
// r [0] ^= ri [0] ^ ( ri [1] << 16) ^ ( ri [2] << 32) ^ ( ri [3] << 49) ;
// r [1] ^= ( ri [3] >> 15) ^ ( ri [4] << 16) ^ ( ri [5] << 35) ;
// r [2] ^= ri [6] ^ ( ri [7] << 23) ^ ( ri [8] << 48) ;
// r [3]

/// Compute redundancy r[] ( XOR over original ) from data d[]
pub fn xe5_cod(d: &[u64]) -> [u64; 4] {
    assert_eq!(d.len(), 4);
    let mut r = [0; 4];

    r
}
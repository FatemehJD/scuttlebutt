// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

// Portions of the below code adapted from the `aesni` crate (version 0.6.0),
// which uses the following license:
//
// Copyright (c) 2017 Artyom Pavlov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::Block;
use std::arch::aarch64::*;

/// AES-128, encryption only.
#[derive(Clone)]
pub struct Aes128 {
    rkeys: [uint8x16_t; 11],
}

macro_rules! xor4 {
    ($b:expr, $key:expr) => {
        $b[0].0 = veorq_u8($b[0].0, $key);
        $b[1].0 = veorq_u8($b[1].0, $key);
        $b[2].0 = veorq_u8($b[2].0, $key);
        $b[3].0 = veorq_u8($b[3].0, $key);
    };
}

macro_rules! aesenc4 {
    ($b:expr, $key:expr) => {
        $b[0].0 = vaeseq_u8($b[0].0, $key);
        $b[1].0 = vaeseq_u8($b[1].0, $key);
        $b[2].0 = vaeseq_u8($b[2].0, $key);
        $b[3].0 = vaeseq_u8($b[3].0, $key);
    };
}

macro_rules! aesenclast4 {
    ($b:expr, $key:expr) => {
        $b[0].0 = vaesmcq_u8($b[0].0);
        $b[1].0 = vaesmcq_u8($b[1].0);
        $b[2].0 = vaesmcq_u8($b[2].0);
        $b[3].0 = vaesmcq_u8($b[3].0);
        $b[0].0 = vaeseq_u8($b[0].0, $key);
        $b[1].0 = vaeseq_u8($b[1].0, $key);
        $b[2].0 = vaeseq_u8($b[2].0, $key);
        $b[3].0 = vaeseq_u8($b[3].0, $key);
    };
}

impl Aes128 {
    /// Create a new `Aes128` object, using `key` as the AES key.
    #[inline]
    pub fn new(key: Block) -> Self {
        let rkeys = expand(key.0);
        Aes128 { rkeys }
    }

    /// Encrypt a block, outputting the ciphertext.
    #[inline(always)]
    pub fn encrypt(&self, m: Block) -> Block {
        let rkeys = self.rkeys;
        unsafe {
            let mut c: uint8x16_t = m.into();
            c = veorq_u8(c, rkeys[0]);
            aesenc4!(c, rkeys[1]);
            aesenc4!(c, rkeys[2]);
            aesenc4!(c, rkeys[3]);
            aesenc4!(c, rkeys[4]);
            aesenc4!(c, rkeys[5]);
            aesenc4!(c, rkeys[6]);
            aesenc4!(c, rkeys[7]);
            aesenc4!(c, rkeys[8]);
            aesenc4!(c, rkeys[9]);
            aesenclast4!(c, rkeys[10]);
            Block(c)
        }
    }

    // ... Rest of the code remains unchanged ...
}

macro_rules! expand_round {
    ($enc_keys:expr, $pos:expr, $round:expr) => {
        let mut t1 = vld1q_u8($enc_keys.as_ptr().offset($pos - 1));
        let mut t2;
        let mut t3;

        t2 = vaesmcq_u8(vaeseq_u8(t1, $round));
        t2 = vextq_u8(t2, t2, 8);
        t3 = vextq_u8(t1, t1, 4);
        t1 = veorq_u8(t1, t3);
        t3 = vextq_u8(t3, t3, 4);
        t1 = veorq_u8(t1, t3);
        t3 = vextq_u8(t3, t3, 4);
        t1 = veorq_u8(t1, t3);
        t1 = veorq_u8(t1, t2);

        vst1q_u8($enc_keys.as_mut_ptr().offset($pos), t1);
    };
}

#[inline(always)]
fn expand(key: uint8x16_t) -> [uint8x16_t; 11] {
    unsafe {
        let mut keys: [uint8x16_t; 11] = std::mem::uninitialized();
        vst1q_u8(keys.as_mut_ptr(), key);
        expand_round!(keys, 1, vdupq_n_u8(0x01));
        expand_round!(keys, 2, vdupq_n_u8(0x02));
        expand_round!(keys, 3, vdupq_n_u8(0x04));
        expand_round!(keys, 4, vdupq_n_u8(0x08));
        expand_round!(keys, 5, vdupq_n_u8(0x10));
        expand_round!(keys, 6, vdupq_n_u8(0x20));
        expand_round!(keys, 7, vdupq_n_u8(0x40));
        expand_round!(keys, 8, vdupq_n_u8(0x80));
        expand_round!(keys, 9, vdupq_n_u8(0x1B));
        expand_round!(keys, 10, vdupq_n_u8(0x36));
        keys
    }
}

union __U128 {
    vector: uint8x16_t,  // or the appropriate AArch64 SIMD type
    bytes: u128,
}

/// Fixed-key AES-128.
pub const FIXED_KEY_AES128: Aes128 = Aes128 {
    rkeys: unsafe {
        [
            (__U128 {
                bytes: 0x15B5_32C2_F193_1C94,
            })
            .vector,
            (__U128 {
                bytes: 0xD754_876D_FE7E_6726,
            })
            .vector,
            (__U128 {
                bytes: 0xA7EB_4F98_1986_CFCF,
            })
            .vector,
            (__U128 {
                bytes: 0x80E6_BBED_F88D_E8C9,
            })
            .vector,
            (__U128 {
                bytes: 0x1210_4B44_43D8_B35C,
            })
            .vector,
            (__U128 {
                bytes: 0xF467_7B3C_8DCB_047B,
            })
            .vector,
            (__U128 {
                bytes: 0x578C_DBAC_AED1_C9DC,
            })
            .vector,
            (__U128 {
                bytes: 0x295D_2051_CF6F_5E25,
            })
            .vector,
            (__U128 {
                bytes: 0x0CE1_FD36_50DE_FFAB,
            })
            .vector,
            (__U128 {
                bytes: 0xDDFA_4FE9_E2CD_2D23,
            })
            .vector,
            (__U128 {
                bytes: 0x96F6_769D_AF14_18D2,
            })
            .vector,
        ]
    },
};

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_aes_128() {
        let key = Block::from(0x3C4FCF098815F7ABA6D2AE2816157E2B);
        let pt = Block::from(0x2A179373117E3DE9969F402EE2BEC16B);
        let cipher = Aes128::new(key);
        let ct = cipher.encrypt(pt);
        assert_eq!(ct, Block::from(0x97EF6624F3CA9EA860367A0DB47BD73A));
    }
}

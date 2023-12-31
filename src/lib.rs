// -*- mode: rust; -*-
//
// This file is part of `scuttlebutt`.
// Copyright © 2019 Galois, Inc.
// See LICENSE for licensing information.

#![allow(clippy::many_single_char_names)]
#![cfg_attr(feature = "nightly", feature(stdsimd))]
#![cfg_attr(feature = "nightly", feature(test))]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", deny(missing_docs))]
#![feature(stdsimd, arm_target_feature)]

//!

mod aes;
mod block;
mod block512;
mod channel;
pub mod cointoss;
pub mod commitment;
mod hash_aes;
mod rand_aes;
pub mod utils;

pub use crate::aes::aes128::{Aes128, FIXED_KEY_AES128};
pub use crate::aes::aes256::Aes256;
pub use crate::block::Block;
pub use crate::block512::Block512;
pub use crate::channel::{AbstractChannel, Channel, SyncChannel, HashChannel, TrackChannel};
pub use crate::hash_aes::{AesHash, AES_HASH};
pub use crate::rand_aes::AesRng;

/// A marker trait denoting that the given scheme is semi-honest secure.
pub trait SemiHonest {}
/// A marker trait denoting that the given scheme is maliciously secure.
pub trait Malicious: SemiHonest {}

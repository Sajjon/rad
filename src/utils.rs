use bip39::Mnemonic;
use primitive_types::U256;
use std::{collections::HashSet, sync::MutexGuard};

use crate::params::Bip39WordCount;

pub fn mnemonic_from_u256(u: &U256, word_count: &Bip39WordCount) -> Mnemonic {
    let mut vec: Vec<u8> = vec![0u8; 32];
    u.to_big_endian(&mut vec);
    vec.drain(0..vec.len() - word_count.byte_count());
    return Mnemonic::from_entropy(&vec).unwrap();
}

pub fn remove<E, F, By>(elements: &Vec<E>, mut from: MutexGuard<HashSet<F>>, by: By) -> ()
where
    By: Fn(&E, &F) -> bool,
{
    (*from).retain(|f| elements.iter().all(|e| by(e, f)))
}

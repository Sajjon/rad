use crate::{
    hdwallet::{vanity_from_childkey, ChildKey, HDWallet},
    params::BruteForceInput,
    run_config::RunConfig,
    utils::remove,
    vanity::*,
};

use std::{
    collections::HashSet,
    ops::Range,
    sync::{Arc, Mutex},
};

use rayon::prelude::{IntoParallelIterator, ParallelIterator};

/// In parallel searches for needles in a haystack, until haystack is empty
///
/// When all needles have been found, `take_while` returns false, thus stopping iteration.
///
/// Needles are created from "needle tips", potential candidates for a needle, and needle
/// tips are created for every iteration from a `u32`.
fn parallel_search<NeedleTip, Needle, TakeWhile, NeedleTipFrom, NeedlesFromTip>(
    range: Range<u32>,
    take_while: TakeWhile,
    needle_tip_from: NeedleTipFrom,
    needles_from_tip: NeedlesFromTip,
) -> Vec<Needle>
where
    TakeWhile: Fn(&u32) -> bool + Sync + Send,
    NeedleTipFrom: Fn(u32) -> NeedleTip + Sync + Send,
    NeedlesFromTip: Fn(NeedleTip) -> Vec<Needle> + Sync + Send,
    NeedleTip: Send,
    Needle: Send,
{
    range
        .into_par_iter()
        .take_any_while(take_while)
        .map(needle_tip_from)
        .flat_map(needles_from_tip)
        .collect()
}

fn parallel_search_addresses<DeriveChild, VanityFromMatchingChild>(
    run_config: RunConfig,
    derive_child: DeriveChild,
    vanity_from_matching_child: VanityFromMatchingChild,
    end_index: u32,
    targets: Arc<Mutex<HashSet<String>>>,
) -> Vec<Vanity>
where
    DeriveChild: Fn(u32) -> ChildKey + Send + Sync,
    VanityFromMatchingChild: Fn(&ChildKey, &String) -> Vanity + Send + Sync,
{
    parallel_search(
        0..end_index,
        |_| !targets.lock().unwrap().is_empty(),
        derive_child,
        |c| {
            let targets = targets.lock().unwrap();
            let mut matches = Vec::<Vanity>::new();
            for target in targets.iter() {
                if c.suffix.ends_with(target) {
                    let vanity = vanity_from_matching_child(&c, target);
                    cond_print(&vanity, &run_config);
                    matches.push(vanity);
                }
            }
            remove(&matches, targets, |v, t| &v.target != t);
            matches
        },
    )
}

pub fn par_find(input: BruteForceInput, run_config: RunConfig) -> Vec<Vanity> {
    if run_config.print_input {
        println!("{input}");
    }

    let wallet = HDWallet::from_entropy(input.clone().int()).unwrap();
    let targets = Arc::new(Mutex::new(input.clone().targets));

    parallel_search_addresses(
        run_config.clone(),
        |i| wallet.derive_child(i),
        |c, t| vanity_from_childkey(c, t, &wallet),
        input.index_end(),
        targets,
    )
}

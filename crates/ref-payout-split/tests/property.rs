//! Property tests for ref-payout-split (org-037).
//!
//! A deterministic xorshift PRNG drives randomized gross amounts and
//! split tables — no external property-test dependency, fully
//! reproducible from the fixed seed. The invariant under test is the
//! crate's core contract: parts always sum EXACTLY to the whole, to
//! the cent, under every caller-chosen remainder rule.

use ref_payout_split::{
    compute_split, PartyId, RemainderRule, SplitTable, TieBreak,
};

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_table(rng: &mut XorShift) -> SplitTable {
    let n = 1 + rng.below(8) as usize; // 1..=8 parties
    let mut entries: Vec<(PartyId, u64)> = (0..n)
        .map(|i| (PartyId::new(format!("party-{i}")).unwrap(), rng.below(1001)))
        .collect();
    if entries.iter().all(|(_, w)| *w == 0) {
        entries[0].1 = 1; // keep total weight > 0
    }
    SplitTable::new(entries).unwrap()
}

fn floors(gross: u64, table: &SplitTable) -> Vec<u64> {
    let total = table.total_weight();
    table
        .entries()
        .iter()
        .map(|(_, w)| (gross as u128 * *w as u128 / total) as u64)
        .collect()
}

#[test]
fn property_parts_always_sum_to_whole_largest_remainder() {
    let mut rng = XorShift(0x9e3779b97f4a7c15);
    for _ in 0..20_000 {
        let gross = rng.below(1_000_001);
        let table = random_table(&mut rng);
        for tie_break in [TieBreak::EarliestInTable, TieBreak::LowestPartyId] {
            let rule = RemainderRule::LargestRemainder { tie_break };
            let parts = compute_split(gross, &table, &rule).unwrap();
            assert_eq!(parts.len(), table.entries().len());
            let sum: u128 = parts.iter().map(|(_, c)| *c as u128).sum();
            assert_eq!(sum, gross as u128, "gross={gross} table={table:?}");
            let fl = floors(gross, &table);
            for (i, ((party, w), (_, c))) in
                table.entries().iter().zip(parts.iter()).enumerate()
            {
                // Each part is floor or floor+1.
                assert!(
                    *c == fl[i] || *c == fl[i] + 1,
                    "party {party} part {c} not floor/floor+1 of {} (gross {gross})",
                    fl[i]
                );
                // A zero-weight party never receives a remainder cent.
                if *w == 0 {
                    assert_eq!(*c, 0, "zero-weight party {party} got {c}");
                }
                let _ = party;
            }
        }
    }
}

#[test]
fn property_parts_always_sum_to_whole_entire_remainder_to() {
    let mut rng = XorShift(0x243f6a8885a308d3);
    for _ in 0..20_000 {
        let gross = rng.below(1_000_001);
        let table = random_table(&mut rng);
        let idx = rng.below(table.entries().len() as u64) as usize;
        let named = table.entries()[idx].0.clone();
        let rule = RemainderRule::EntireRemainderTo { party: named };
        let parts = compute_split(gross, &table, &rule).unwrap();
        let sum: u128 = parts.iter().map(|(_, c)| *c as u128).sum();
        assert_eq!(sum, gross as u128, "gross={gross} table={table:?}");
        let fl = floors(gross, &table);
        for (i, (_, c)) in parts.iter().enumerate() {
            if i != idx {
                // Non-named parties receive exactly their floor.
                assert_eq!(*c, fl[i], "non-named party {i} part {c} != floor {}", fl[i]);
            } else {
                assert!(*c >= fl[i]);
            }
        }
    }
}

#[test]
fn property_deterministic_same_inputs_same_parts() {
    let mut rng = XorShift(0x452821e638d01377);
    for _ in 0..1_000 {
        let gross = rng.below(1_000_001);
        let table = random_table(&mut rng);
        let rule = RemainderRule::LargestRemainder {
            tie_break: TieBreak::LowestPartyId,
        };
        let a = compute_split(gross, &table, &rule).unwrap();
        let b = compute_split(gross, &table, &rule).unwrap();
        assert_eq!(a, b);
    }
}

// ---------------------------------------------------------------------
// Named cases.
// ---------------------------------------------------------------------

fn table(entries: &[(&str, u64)]) -> SplitTable {
    SplitTable::new(
        entries
            .iter()
            .map(|(p, w)| (PartyId::new(*p).unwrap(), *w))
            .collect(),
    )
    .unwrap()
}

fn cents(parts: &[(PartyId, u64)]) -> Vec<u64> {
    parts.iter().map(|(_, c)| *c).collect()
}

/// The live Canswer split: 69% customer / 26% driver / 5% platform at
/// BC's 10c per container. 100 bottles = 1000 cents gross, and the
/// split must be exactly $6.90 / $2.60 / $0.50.
#[test]
fn canswer_live_split_100_bottles() {
    let t = table(&[("customer", 69), ("driver", 26), ("platform", 5)]);
    let rule = RemainderRule::LargestRemainder {
        tie_break: TieBreak::EarliestInTable,
    };
    let parts = compute_split(1000, &t, &rule).unwrap();
    assert_eq!(cents(&parts), vec![690, 260, 50]);
    assert_eq!(parts[0].0.as_str(), "customer");
    assert_eq!(parts[1].0.as_str(), "driver");
    assert_eq!(parts[2].0.as_str(), "platform");
}

/// The VanCan programme split (vancan_split.json): canner 69 /
/// driver 21 / vancan 10. On a gross with a remainder (999 cents):
/// floors are 689 / 209 / 99 with fractional remainders 31 / 79 / 90
/// (scaled), so the 2 leftover cents go to vancan and driver.
#[test]
fn vancan_programme_split_with_remainder() {
    let t = table(&[("canner", 69), ("driver", 21), ("vancan", 10)]);
    let rule = RemainderRule::LargestRemainder {
        tie_break: TieBreak::EarliestInTable,
    };
    assert_eq!(cents(&compute_split(1000, &t, &rule).unwrap()), vec![690, 210, 100]);
    assert_eq!(cents(&compute_split(999, &t, &rule).unwrap()), vec![689, 210, 100]);
}

/// One cent across three equal parties: exactly one party receives
/// it, chosen by the caller's rule — never split, never duplicated,
/// never lost.
#[test]
fn one_cent_three_parties() {
    let t = table(&[("a", 1), ("b", 1), ("c", 1)]);
    // Largest remainder, earliest-in-table tie-break: "a" wins.
    let rule = RemainderRule::LargestRemainder {
        tie_break: TieBreak::EarliestInTable,
    };
    assert_eq!(cents(&compute_split(1, &t, &rule).unwrap()), vec![1, 0, 0]);
    // Same rule, lowest-party-id tie-break on a reordered table:
    // "a" still wins, wherever it sits.
    let t2 = table(&[("c", 1), ("a", 1), ("b", 1)]);
    let rule2 = RemainderRule::LargestRemainder {
        tie_break: TieBreak::LowestPartyId,
    };
    let parts = compute_split(1, &t2, &rule2).unwrap();
    assert_eq!(parts[1].1, 1);
    assert_eq!(parts.iter().map(|(_, c)| *c).sum::<u64>(), 1);
    // Entire remainder to a named party: "c" wins outright.
    let rule3 = RemainderRule::EntireRemainderTo {
        party: PartyId::new("c").unwrap(),
    };
    assert_eq!(cents(&compute_split(1, &t, &rule3).unwrap()), vec![0, 0, 1]);
    // Two cents across three parties: two parties get one each.
    assert_eq!(cents(&compute_split(2, &t, &rule).unwrap()), vec![1, 1, 0]);
}

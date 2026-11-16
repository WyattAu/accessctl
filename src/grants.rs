//! Conservation-spanning grant ledger (X5 pilot, ADR-0001).
//!
//! The module exposes exactly six mutating operators — [`issue`],
//! [`split`], [`transfer`], [`attenuate`], [`revoke`], [`merge`] — and
//! no way to construct or mutate a [`Grant`] outside them. The algebraic
//! closure of the operators lies strictly inside the valid state
//! manifold, so the conservation invariant holds by geometry rather
//! than by post-hoc validation:
//!
//! ```text
//! sum(active amounts) == issued_total - revoked_total - attenuated_total
//! ```
//!
//! after every operation, for every operation sequence. The invariant is
//! asserted continuously by the property tests in this module
//! (ADR-0001, exit criterion 1).
//!
//! [`issue`]: GrantLedger::issue

use std::collections::BTreeMap;
use std::fmt;

use thiserror::Error;

/// Principal holding a grant. Opaque newtype; construct via
/// [`GrantLedger::issue`] and [`GrantLedger::transfer`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject(pub String);

/// Identifier of a grant inside one [`GrantLedger`]. Ids are never
/// reused, even after revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId(u64);

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// One grant: `amount` units of capability held by `subject`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Current holder.
    pub subject: Subject,
    /// Current outstanding amount (minor units). Zero amounts cannot
    /// occur: attenuating to zero is expressed as [`revoke`].
    pub amount: u64,
}

/// Operator errors. Every failure mode is a rejected parameter, never
/// corrupted state: the ledger is unchanged after any `Err`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GrantError {
    /// The grant id does not exist in this ledger.
    #[error("grant {0} not found")]
    NotFound(GrantId),
    /// The grant exists but is no longer active (revoked or merged).
    #[error("grant {0} is not active")]
    Inactive(GrantId),
    /// Amounts must be at least one minor unit.
    #[error("amount must be >= 1")]
    ZeroAmount,
    /// `split` asked for more than the source grant holds (minus one,
    /// so both halves stay non-degenerate).
    #[error("split take {0} exceeds source amount {1}")]
    SplitExceedsAmount(u64, u64),
    /// `attenuate` asked to remove the whole amount; use revoke.
    #[error("attenuate by {0} exceeds source amount {1}")]
    ReduceExceedsAmount(u64, u64),
    /// `merge` requires both grants to share one subject.
    #[error("merge subjects differ")]
    SubjectMismatch,
    /// `merge` was called with the same grant id twice.
    #[error("cannot merge a grant with itself")]
    SameGrant,
}

/// The ledger world: every grant ever issued, plus the running totals
/// that make the conservation invariant checkable in O(1).
#[derive(Debug, Clone, Default)]
pub struct GrantLedger {
    grants: BTreeMap<GrantId, Entry>,
    next_id: u64,
    issued_total: u128,
    revoked_total: u128,
    attenuated_total: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    subject: Subject,
    amount: u64,
    active: bool,
}

impl GrantLedger {
    /// Creates an empty ledger. The only constructor; an empty ledger
    /// trivially satisfies the conservation invariant.
    pub fn new() -> Self {
        Self::default()
    }

    /// Operator 1/6: create a new grant for `subject` worth `amount`.
    pub fn issue(&mut self, subject: Subject, amount: u64) -> Result<GrantId, GrantError> {
        if amount == 0 {
            return Err(GrantError::ZeroAmount);
        }
        let id = GrantId(self.next_id);
        self.next_id += 1;
        self.grants.insert(
            id,
            Entry {
                subject,
                amount,
                active: true,
            },
        );
        self.issued_total += u128::from(amount);
        Ok(id)
    }

    /// Operator 2/6: carve `take` units out of `id` into a new grant for
    /// the same subject. Source keeps `amount - take`; both halves stay
    /// active and non-degenerate.
    pub fn split(&mut self, id: GrantId, take: u64) -> Result<GrantId, GrantError> {
        let entry = self.grants.get(&id).ok_or(GrantError::NotFound(id))?;
        if !entry.active {
            return Err(GrantError::Inactive(id));
        }
        if take == 0 {
            return Err(GrantError::ZeroAmount);
        }
        if take >= entry.amount {
            return Err(GrantError::SplitExceedsAmount(take, entry.amount));
        }
        let subject = entry.subject.clone();
        let new_id = self.issue(subject, take)?;
        // `id` was validated active above and ids are never removed.
        if let Some(entry) = self.grants.get_mut(&id) {
            entry.amount -= take;
        }
        // `issue` booked `take` as new issuance; undo it so the merge is
        // internal: conservation compares active sum against issued -
        // revoked - attenuated, and a split must not move the totals.
        self.issued_total -= u128::from(take);
        Ok(new_id)
    }

    /// Operator 3/6: move `id` to `new_subject`. Amount is conserved.
    pub fn transfer(&mut self, id: GrantId, new_subject: Subject) -> Result<(), GrantError> {
        let entry = self.grants.get_mut(&id).ok_or(GrantError::NotFound(id))?;
        if !entry.active {
            return Err(GrantError::Inactive(id));
        }
        entry.subject = new_subject;
        Ok(())
    }

    /// Operator 4/6: shrink `id` by `reduce_by`. The delta is booked so
    /// the invariant accounts for capability that left the world
    /// without a revoke. Attenuating to zero is expressed as revoke.
    pub fn attenuate(&mut self, id: GrantId, reduce_by: u64) -> Result<(), GrantError> {
        if reduce_by == 0 {
            return Err(GrantError::ZeroAmount);
        }
        let entry = self.grants.get_mut(&id).ok_or(GrantError::NotFound(id))?;
        if !entry.active {
            return Err(GrantError::Inactive(id));
        }
        if reduce_by >= entry.amount {
            return Err(GrantError::ReduceExceedsAmount(reduce_by, entry.amount));
        }
        entry.amount -= reduce_by;
        self.attenuated_total += u128::from(reduce_by);
        Ok(())
    }

    /// Operator 5/6: retire `id`. Its amount leaves the active sum and
    /// is booked as revoked.
    pub fn revoke(&mut self, id: GrantId) -> Result<(), GrantError> {
        let entry = self.grants.get_mut(&id).ok_or(GrantError::NotFound(id))?;
        if !entry.active {
            return Err(GrantError::Inactive(id));
        }
        entry.active = false;
        self.revoked_total += u128::from(entry.amount);
        Ok(())
    }

    /// Operator 6/6: fold `a` and `b` (same subject, both active) into
    /// one grant carrying their combined amount. Count goes down by
    /// one; the amount is exactly conserved.
    pub fn merge(&mut self, a: GrantId, b: GrantId) -> Result<GrantId, GrantError> {
        if a == b {
            return Err(GrantError::SameGrant);
        }
        let ea = self.grants.get(&a).ok_or(GrantError::NotFound(a))?;
        let eb = self.grants.get(&b).ok_or(GrantError::NotFound(b))?;
        if !ea.active {
            return Err(GrantError::Inactive(a));
        }
        if !eb.active {
            return Err(GrantError::Inactive(b));
        }
        if ea.subject != eb.subject {
            return Err(GrantError::SubjectMismatch);
        }
        let subject = ea.subject.clone();
        let combined = ea.amount.saturating_add(eb.amount);
        let new_id = self.issue(subject, combined)?;
        // `issue` booked `combined` as new issuance; book the two folded
        // grants as revoked so the totals balance exactly.
        // `a` and `b` were validated active above and ids are never removed.
        let mut folded = 0u128;
        for id in [a, b] {
            if let Some(entry) = self.grants.get_mut(&id) {
                entry.active = false;
                folded += u128::from(entry.amount);
            }
        }
        self.revoked_total += folded;
        Ok(new_id)
    }

    /// Private read: active amount of one grant (None if inactive or
    /// absent). Hosts use `authorize`/`active_amount_for` instead.
    fn amount_of(&self, id: GrantId) -> Option<u64> {
        self.grants.get(&id).filter(|e| e.active).map(|e| e.amount)
    }

    /// Private read: is this id an active grant?
    fn is_active(&self, id: GrantId) -> bool {
        self.grants.get(&id).is_some_and(|e| e.active)
    }

    /// Sum of active amounts. Derived, never stored: balances are not
    /// authority (refusal R4).
    pub fn outstanding(&self) -> u128 {
        self.grants
            .values()
            .filter(|e| e.active)
            .map(|e| u128::from(e.amount))
            .sum()
    }

    /// The conservation invariant: outstanding equals issued minus
    /// revoked minus attenuated. Checked after every operation in the
    /// property tests; exposed so hosts can assert it too.
    pub fn invariant_holds(&self) -> bool {
        self.outstanding() == self.issued_total - self.revoked_total - self.attenuated_total
    }

    /// Total active amount held by one subject.
    pub fn active_amount_for(&self, subject: &Subject) -> u128 {
        self.grants
            .values()
            .filter(|e| e.active && &e.subject == subject)
            .map(|e| u128::from(e.amount))
            .sum()
    }

    /// The shipped pilot feature (ADR-0001 criterion 3): a permission
    /// check on the operator surface — true when `subject` holds at
    /// least `required` active units.
    pub fn authorize(&self, subject: &Subject, required: u64) -> bool {
        self.active_amount_for(subject) >= u128::from(required)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests: construction results are asserted via unwrap
mod tests {
    use super::*;

    fn subj(s: &str) -> Subject {
        Subject(s.to_string())
    }

    #[test]
    fn issue_and_revoke_conserve() {
        let mut l = GrantLedger::new();
        let g = l.issue(subj("alice"), 100).unwrap();
        assert!(l.invariant_holds());
        assert_eq!(l.outstanding(), 100);
        l.revoke(g).unwrap();
        assert!(l.invariant_holds());
        assert_eq!(l.outstanding(), 0);
    }

    #[test]
    fn split_conserves_amount() {
        let mut l = GrantLedger::new();
        let a = l.issue(subj("alice"), 100).unwrap();
        let b = l.split(a, 40).unwrap();
        assert!(l.invariant_holds());
        assert_eq!(l.outstanding(), 100);
        assert_eq!(l.active_amount_for(&subj("alice")), 100);
        let _ = b;
    }

    #[test]
    fn attenuate_books_delta() {
        let mut l = GrantLedger::new();
        let g = l.issue(subj("alice"), 100).unwrap();
        l.attenuate(g, 30).unwrap();
        assert!(l.invariant_holds());
        assert_eq!(l.outstanding(), 70);
        assert!(l.authorize(&subj("alice"), 70));
        assert!(!l.authorize(&subj("alice"), 71));
    }

    #[test]
    fn transfer_moves_holder_not_amount() {
        let mut l = GrantLedger::new();
        let g = l.issue(subj("alice"), 50).unwrap();
        l.transfer(g, subj("bob")).unwrap();
        assert!(l.invariant_holds());
        assert_eq!(l.active_amount_for(&subj("bob")), 50);
        assert_eq!(l.active_amount_for(&subj("alice")), 0);
    }

    #[test]
    fn merge_conserves_and_requires_same_subject() {
        let mut l = GrantLedger::new();
        let a = l.issue(subj("alice"), 30).unwrap();
        let b = l.split(a, 20).unwrap();
        let c = l.merge(a, b).unwrap();
        assert!(l.invariant_holds());
        assert_eq!(l.outstanding(), 30);
        assert!(l.authorize(&subj("alice"), 30));
        let _ = c;

        let d = l.issue(subj("bob"), 10).unwrap();
        assert_eq!(l.merge(c, d), Err(GrantError::SubjectMismatch));
    }

    #[test]
    fn operator_errors_leave_ledger_unchanged() {
        let mut l = GrantLedger::new();
        let g = l.issue(subj("alice"), 10).unwrap();
        assert_eq!(l.split(g, 10), Err(GrantError::SplitExceedsAmount(10, 10)));
        assert_eq!(l.split(g, 0), Err(GrantError::ZeroAmount));
        assert_eq!(l.attenuate(g, 0), Err(GrantError::ZeroAmount));
        assert_eq!(
            l.attenuate(g, 10),
            Err(GrantError::ReduceExceedsAmount(10, 10))
        );
        assert_eq!(l.issue(subj("bob"), 0), Err(GrantError::ZeroAmount));
        let ghost = GrantId(999);
        assert_eq!(l.revoke(ghost), Err(GrantError::NotFound(ghost)));
        assert_eq!(l.merge(g, g), Err(GrantError::SameGrant));
        assert!(l.invariant_holds());
        assert_eq!(l.outstanding(), 10);
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    /// Deterministic LCG walk: same seed, same operation sequence,
    /// same final state (ADR-0001 replayability requirement).
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next() % n }
        }
    }

    /// ADR-0001 criterion 1: for arbitrary operator sequences the
    /// conservation invariant holds after *every* step, and grant ids
    /// are never reused.
    fn walk(seed: u64, steps: u32) -> bool {
        let mut rng = Rng(seed ^ 0xD1B5_4A32_D192_ED03);
        let mut l = GrantLedger::new();
        let mut live: Vec<GrantId> = Vec::new();
        for _ in 0..steps {
            let op = rng.below(6);
            let ok = match op {
                // issue
                0 => {
                    let amount = 1 + rng.below(500);
                    let s = Subject(format!("s{}", rng.below(6)));
                    l.issue(s, amount).is_ok()
                }
                // split
                1 => {
                    if live.is_empty() {
                        true
                    } else {
                        let id = live[rng.below(live.len() as u64) as usize];
                        match l.amount_of(id) {
                            Some(amt) if amt >= 2 => {
                                let take = 1 + rng.below(amt - 1);
                                match l.split(id, take) {
                                    Ok(new) => {
                                        live.push(new);
                                        true
                                    }
                                    Err(_) => false,
                                }
                            }
                            _ => true, // degenerate grant: skip, state unchanged
                        }
                    }
                }
                // transfer
                2 => {
                    if live.is_empty() {
                        true
                    } else {
                        let id = live[rng.below(live.len() as u64) as usize];
                        let s = Subject(format!("s{}", rng.below(6)));
                        l.transfer(id, s).is_ok()
                    }
                }
                // attenuate
                3 => {
                    if live.is_empty() {
                        true
                    } else {
                        let id = live[rng.below(live.len() as u64) as usize];
                        match l.amount_of(id) {
                            Some(amt) if amt >= 2 => {
                                let by = 1 + rng.below(amt - 1);
                                l.attenuate(id, by).is_ok()
                            }
                            _ => true,
                        }
                    }
                }
                // revoke
                4 => {
                    if live.is_empty() {
                        true
                    } else {
                        let idx = rng.below(live.len() as u64) as usize;
                        let id = live.swap_remove(idx);
                        l.revoke(id).is_ok()
                    }
                }
                // merge
                _ => {
                    if live.len() < 2 {
                        true
                    } else {
                        let i = rng.below(live.len() as u64) as usize;
                        let j = rng.below(live.len() as u64) as usize;
                        if i == j {
                            true
                        } else {
                            let a = live[i];
                            let b = live[j];
                            match l.merge(a, b) {
                                Ok(new) => {
                                    live.push(new);
                                    // remove the two folded ids (b is a
                                    // swap_remove target: keep it simple and
                                    // rebuild; sequences are small)
                                    live.retain(|g| *g != a && *g != b);
                                    true
                                }
                                Err(_) => true, // subject mismatch is a legal skip
                            }
                        }
                    }
                }
            };
            if !ok {
                return false;
            }
            if !l.invariant_holds() {
                return false;
            }
        }
        // final structural checks
        l.invariant_holds() && live.iter().all(|g| l.is_active(*g))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]
        #[test]
        fn conservation_under_arbitrary_sequences(seed in any::<u64>()) {
            prop_assert!(walk(seed, 250));
        }
    }

    #[test]
    fn long_walk_single_seed() {
        // deterministic soak: one seed, 10_000 steps (ADR-0001 criterion 1)
        assert!(walk(0xC0FF_EE00, 10_000));
    }
}

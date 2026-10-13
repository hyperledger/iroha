//! One closed current-value/first-preimage insertion under two original writers.
//!
//! This is an insertion boundary, not complete MV, World or carrier admission.
//! The caller binds the maps to its intended roles and one original budget; the
//! generic engine can authenticate retained map owners, not an external pool.

use super::*;
use crate::internals::bptree::cursor::CursorCheckpoint;

#[path = "borrowed_pair.rs"]
mod borrowed_pair;

/// Refusal before either original private map is mutated.
#[derive(Debug)]
pub enum PairInsertError<E> {
    /// The current map refused its exact retained owner.
    Current(OwnedWriteError),
    /// The undo map refused its exact retained owner.
    Undo(OwnedWriteError),
    /// The complete joined demand or a required checkpoint cannot be planned.
    Planning(PlanningError),
    /// The one original provider refused the entire checked joined demand.
    Refused(E),
}

struct PairPlan {
    current: EditPlan,
    undo: Option<EditPlan>,
    demand: AllocationDemand,
}

fn plan_pair<K, V, P>(
    current: &CursorWrite<K, V, Prepaid<P>>,
    undo: &CursorWrite<K, Option<V>, Prepaid<P>>,
    key: &K,
) -> Result<PairPlan, PlanningError>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    current.assert_operable();
    undo.assert_operable();
    checked_next_generation(current.get_txid()).ok_or(PlanningError::Overflow)?;
    // An existing None is a retained first touch, not a missing undo entry.
    let first_touch = !undo.contains_key(key);
    if first_touch {
        checked_next_generation(undo.get_txid()).ok_or(PlanningError::Overflow)?;
    }
    let current_plan = plan_edit::<K, V, P>(current, key)?;
    let mut demand = current_plan.demand;
    let undo_plan = if first_touch {
        let plan = plan_edit::<K, Option<V>, P>(undo, key)?;
        demand.add(plan.demand, 1)?;
        <P as ClonePlanning<K, Option<V>>>::plan_key(key, &mut demand)?;
        if let Some(value) = current.search(key) {
            <P as ClonePlanning<K, V>>::plan_value(value, &mut demand)?;
        }
        Some(plan)
    } else {
        None
    };
    Ok(PairPlan {
        current: current_plan,
        undo: undo_plan,
        demand,
    })
}

// The caller owns both original checkpoints/guards before entering and through
// final cleanup. Tests can drop those same checkpoints after this private phase
// to prove allocation-free abort; the public operation applies them below.
fn execute_pair<K, V, P>(
    current: &mut CursorCheckpoint<'_, K, V, Prepaid<P>>,
    undo: Option<&mut CursorCheckpoint<'_, K, Option<V>, Prepaid<P>>>,
    plan: PairPlan,
    key: K,
    value: V,
    mut provider: P,
) -> Option<V>
where
    K: Clone + Ord + Debug,
    V: Clone,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    let undo_input = if plan.undo.is_some() {
        let copied_key = <P as NodeCloning<K, Option<V>>>::clone_key(&mut provider, &key);
        let old_value = current
            .as_ref()
            .search(&key)
            .map(|old| <P as NodeCloning<K, V>>::clone_value(&mut provider, old));
        Some((copied_key, old_value))
    } else {
        None
    };
    let (current_cursor, current_saved) = current.edit_parts();
    let previous = execute_edit(
        current_cursor,
        key,
        value,
        provider,
        plan.current,
        Some(current_saved),
    );
    provider = current_cursor.take_completed_admitted_funding();
    let undo_cursor = match (undo, plan.undo, undo_input) {
        (Some(checkpoint), Some(plan), Some((key, value))) => {
            let (cursor, saved) = checkpoint.edit_parts();
            let replaced = execute_edit(cursor, key, value, provider, plan, Some(saved));
            provider = cursor.take_completed_admitted_funding();
            assert!(
                replaced.is_none(),
                "planned first touch replaced an undo entry"
            );
            Some(cursor)
        }
        (None, None, None) => None,
        _ => unreachable!("exact private first-touch plan and checkpoint"),
    };
    // Both cursors remain failed while their single original provider drops.
    // Any panic unwinds both checkpoints and physical locks; no owner escapes.
    drop(provider);
    current_cursor.seal_joined_admitted_edit();
    if let Some(cursor) = undo_cursor {
        cursor.seal_joined_admitted_edit();
    }
    previous
}

impl<K, V, P> BptreeMap<K, V, Prepaid<P>>
where
    K: Clone + Ord + Debug + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Insert a private current value and retain its first preimage exactly once.
    ///
    /// Reattaches undo then current without allocation or waiting. Before any
    /// checkpoint, clone or edit, the one callback admits the checked sum of both
    /// required edits and the first-preimage copies. Its move-only provider is
    /// consumed across the two edits without reserving again. An existing undo
    /// entry, including None, is neither edited nor checkpointed.
    ///
    /// Refusal returns both exact retained owners and the unchanged owned input.
    /// Successful results retain the original cursor/reader shells and remain
    /// unpublished. A panic during planning, cloning, editing or cleanup releases
    /// neither partial successor: both original locks unwind and poison. Keep
    /// this synchronous operation inside the original budget's refund-notification
    /// deferral scope so refunds cannot wake a retry while either lock is held.
    ///
    /// The enclosing storage owner must supply the intended current/undo maps and
    /// one provider from their common original budget. This generic API does not
    /// authenticate a budget identity or admit removal, clear, arbitrary payload
    /// mutation, future instructions or a complete carrier.
    pub fn try_insert_with_undo_owned_admitted<E>(
        &self,
        current: BptreeMapOwned<K, V, Prepaid<P>>,
        undo_map: &BptreeMap<K, Option<V>, Prepaid<P>>,
        undo: BptreeMapOwned<K, Option<V>, Prepaid<P>>,
        key: K,
        value: V,
        admit: impl FnOnce(AllocationDemand) -> Result<P, E>,
    ) -> OwnedPairInsertResult<K, V, P, E> {
        let mut undo_writer = match undo_map.inner.try_write_owned(undo.inner) {
            Ok(writer) => writer,
            Err((inner, error)) => {
                return Err((
                    (current, BptreeMapOwned { inner }, key, value),
                    PairInsertError::Undo(error),
                ));
            }
        };
        let mut current_writer = match self.inner.try_write_owned(current.inner) {
            Ok(writer) => writer,
            Err((inner, error)) => {
                return Err((
                    (
                        BptreeMapOwned { inner },
                        BptreeMapOwned {
                            inner: undo_writer.detach(),
                        },
                        key,
                        value,
                    ),
                    PairInsertError::Current(error),
                ));
            }
        };
        let prepared = (|| {
            let plan = plan_pair::<K, V, P>(current_writer.as_ref(), undo_writer.as_ref(), &key)
                .map_err(PairInsertError::Planning)?;
            let provider = admit(plan.demand).map_err(PairInsertError::Refused)?;
            Ok((plan, provider))
        })();
        let (plan, provider) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err((
                    (
                        BptreeMapOwned {
                            inner: current_writer.detach(),
                        },
                        BptreeMapOwned {
                            inner: undo_writer.detach(),
                        },
                        key,
                        value,
                    ),
                    error,
                ));
            }
        };
        let previous = {
            let mut current_checkpoint = current_writer
                .as_mut()
                .checkpoint()
                .expect("same held current generation preflighted before admission");
            let mut undo_checkpoint = if plan.undo.is_some() {
                Some(
                    undo_writer
                        .as_mut()
                        .checkpoint()
                        .expect("same held undo generation preflighted before admission"),
                )
            } else {
                None
            };
            let previous = execute_pair(
                &mut current_checkpoint,
                undo_checkpoint.as_mut(),
                plan,
                key,
                value,
                provider,
            );
            // Neither writer may detach until cleanup and both private applies have
            // completed. A second apply panic still owns and aborts the first writer.
            current_checkpoint.apply();
            if let Some(checkpoint) = undo_checkpoint {
                checkpoint.apply();
            }
            previous
        };
        Ok((
            (
                BptreeMapOwned {
                    inner: current_writer.detach(),
                },
                BptreeMapOwned {
                    inner: undo_writer.detach(),
                },
            ),
            previous,
        ))
    }
}

#[cfg(all(test, not(miri)))]
#[path = "pair_admission_tests.rs"]
mod tests;

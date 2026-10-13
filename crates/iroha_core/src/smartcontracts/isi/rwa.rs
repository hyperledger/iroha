//! This module contains RWA instructions and queries implementations.
use super::prelude::*;
use iroha_model_base::name::Name;
use iroha_telemetry::metrics;
/// ISI module contains all instructions related to RWA lots.
pub mod isi {
    use super::*;
    use crate::smartcontracts::isi::account_admission::ensure_receiving_account;
    use iroha_data_model::{
        IntoKeyValue,
        isi::{
            error::RepetitionError,
            rwa::{
                ForceTransferRwa, FreezeRwa, HoldRwa, MergeRwas, RedeemRwa, RegisterRwa,
                ReleaseRwa, SetRwaControls, TransferRwa, UnfreezeRwa,
            },
        },
        query::error::FindError,
        rwa::NewRwa,
        rwa::RwaEntry,
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::numeric::Quantity;
    use iroha_telemetry::metrics;
    use std::collections::BTreeSet;
    fn ensure_positive_quantity(quantity: &Quantity, context: &str) -> Result<(), Error> {
        if quantity.is_zero() {
            return Err(Error::InvariantViolation(
                format!("{context} quantity must be greater than zero").into(),
            ));
        }
        Ok(())
    }
    fn ensure_quantity_available(
        available: &Quantity,
        quantity: &Quantity,
        message: impl Into<String>,
    ) -> Result<(), Error> {
        if quantity > available {
            return Err(Error::InvariantViolation(message.into().into()));
        }
        Ok(())
    }
    fn ensure_quantity_matches_spec(
        spec: NumericSpec,
        quantity: &Quantity,
        context: &str,
    ) -> Result<(), Error> {
        spec.check(quantity.as_numeric()).map_err(|err| {
            Error::InvariantViolation(
                format!("{context} quantity does not satisfy numeric spec: {err}").into(),
            )
        })
    }
    fn authoritative_rwa(entry: RwaEntry<'_>) -> Rwa {
        let value = entry.value().clone().into_inner();
        Rwa {
            id: entry.id().clone(),
            quantity: value.quantity,
            spec: value.spec,
            primary_reference: value.primary_reference,
            status: value.status,
            metadata: value.metadata,
            parents: value.parents,
            controls: value.controls,
            owned_by: value.owned_by,
            is_frozen: value.is_frozen,
            held_quantity: value.held_quantity,
        }
    }
    fn load_rwa(world: &impl WorldReadOnly, id: &RwaId) -> Result<Rwa, Error> {
        world.rwa(id).map(authoritative_rwa).map_err(Error::from)
    }
    fn authority_is_controller(
        world: &impl WorldReadOnly,
        authority: &AccountId,
        controls: &RwaControlPolicy,
    ) -> bool {
        controls.controller_accounts.contains(authority)
            || world
                .account_roles_iter(authority)
                .any(|role_id| controls.controller_roles.contains(role_id))
    }
    fn ensure_owner_or_controller(
        world: &impl WorldReadOnly,
        authority: &AccountId,
        rwa: &Rwa,
        action: &str,
    ) -> Result<bool, Error> {
        let is_controller = authority_is_controller(world, authority, rwa.controls());
        if authority == rwa.owned_by() || is_controller {
            Ok(is_controller)
        } else {
            Err(Error::InvariantViolation(
                format!("{action} requires the RWA owner or a configured controller").into(),
            ))
        }
    }
    fn ensure_controller_enabled(
        world: &impl WorldReadOnly,
        authority: &AccountId,
        rwa: &Rwa,
        enabled: bool,
        action: &str,
    ) -> Result<(), Error> {
        if !enabled {
            return Err(Error::InvariantViolation(
                format!("{action} is disabled for RWA {}", rwa.id()).into(),
            ));
        }
        if authority_is_controller(world, authority, rwa.controls()) {
            Ok(())
        } else {
            Err(Error::InvariantViolation(
                format!("{action} requires a configured RWA controller").into(),
            ))
        }
    }
    fn child_from_parent(
        parent: &Rwa,
        child_id: RwaId,
        quantity: Quantity,
        owner: AccountId,
    ) -> Rwa {
        let mut child = Rwa::new(
            child_id,
            quantity.clone(),
            parent.spec.clone(),
            parent.primary_reference().clone(),
            parent.status().clone(),
            parent.metadata().clone(),
            vec![RwaParentRef::new(parent.id().clone(), quantity)],
            parent.controls().clone(),
            owner,
        );
        child.is_frozen = false;
        child.held_quantity = Quantity::zero();
        child
    }
    fn child_from_merge(
        child_id: RwaId,
        owner: AccountId,
        quantity: Quantity,
        spec: NumericSpec,
        primary_reference: String,
        status: Option<Name>,
        metadata: Metadata,
        parents: Vec<RwaParentRef>,
    ) -> Rwa {
        let mut child = Rwa::new(
            child_id,
            quantity,
            spec,
            primary_reference,
            status,
            metadata,
            parents,
            RwaControlPolicy::default(),
            owner,
        );
        child.is_frozen = false;
        child.held_quantity = Quantity::zero();
        child
    }
    impl Execute for RegisterRwa {
        #[metrics(+"register_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let NewRwa {
                domain,
                quantity,
                spec,
                primary_reference,
                status,
                metadata,
                parents,
                controls,
            } = self.rwa;
            crate::smartcontracts::limits::enforce_metadata_value_sizes(
                state_transaction,
                &metadata,
            )?;
            let _ = state_transaction.world.domain(&domain)?;
            ensure_positive_quantity(&quantity, "register")?;
            ensure_quantity_matches_spec(spec, &quantity, "register")?;
            for parent in &parents {
                ensure_positive_quantity(parent.quantity(), "register parent")?;
                ensure_quantity_matches_spec(spec, parent.quantity(), "register parent")?;
                if parent.rwa().domain() != &domain {
                    return Err(Error::InvariantViolation(
                        "register parent domain must match the child domain".into(),
                    ));
                }
                let _ = state_transaction.world.rwa(parent.rwa())?;
            }
            let rwa_id = state_transaction.next_generated_rwa_id(&domain, RegisterRwa::WIRE_ID)?;
            if state_transaction.world.rwa(&rwa_id).is_ok() {
                return Err(RepetitionError {
                    instruction: InstructionType::Custom,
                    id: IdBox::RwaId(rwa_id),
                }
                .into());
            }
            let rwa = NewRwa::new(
                domain,
                quantity,
                spec,
                primary_reference,
                status,
                metadata,
                parents,
                controls,
            )
            .build(rwa_id, authority.clone());
            let (id, value) = rwa.clone().into_key_value();
            state_transaction.world.insert_rwa_entry(id, value);
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Rwa(RwaEvent::Created(rwa))));
            Ok(())
        }
    }
    impl Execute for TransferRwa {
        #[metrics(+"transfer_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let TransferRwa {
                source,
                rwa,
                quantity,
                destination,
            } = self;
            state_transaction.world.account(&source)?;
            let _created =
                ensure_receiving_account(authority, &destination, None, state_transaction)?;
            ensure_positive_quantity(&quantity, "transfer")?;
            let source_lot = load_rwa(&state_transaction.world, &rwa)?;
            let is_controller = ensure_owner_or_controller(
                &state_transaction.world,
                authority,
                &source_lot,
                "transfer",
            )?;
            ensure_quantity_matches_spec(source_lot.spec.clone(), &quantity, "transfer")?;
            if source_lot.owned_by != source {
                return Err(Error::InvariantViolation(
                    format!(
                        "source account {source} does not own RWA {}",
                        source_lot.id()
                    )
                    .into(),
                ));
            }
            if source_lot.is_frozen && !is_controller {
                return Err(Error::InvariantViolation(
                    format!("RWA {} is frozen", source_lot.id()).into(),
                ));
            }
            let available = source_lot.available_quantity().ok_or_else(|| {
                Error::InvariantViolation(
                    format!(
                        "RWA {} has invalid held quantity accounting",
                        source_lot.id()
                    )
                    .into(),
                )
            })?;
            ensure_quantity_available(
                &available,
                &quantity,
                format!(
                    "transfer quantity exceeds available quantity for RWA {}",
                    source_lot.id()
                ),
            )?;
            if quantity == source_lot.quantity && source_lot.held_quantity.is_zero() {
                {
                    let rwa_mut = state_transaction.world.rwa_mut(&rwa)?;
                    rwa_mut.owned_by = destination.clone();
                }
                state_transaction.world.replace_rwa_owner_index(
                    &rwa,
                    &source_lot.owned_by,
                    &destination,
                );
                state_transaction.world.emit_events(Some(DomainEvent::Rwa(
                    RwaEvent::OwnerChanged(RwaOwnerChanged {
                        rwa,
                        new_owner: destination,
                    }),
                )));
                return Ok(());
            }
            let new_quantity =
                source_lot
                    .quantity
                    .clone()
                    .checked_sub(&quantity)
                    .map_err(|_| {
                        Error::InvariantViolation(
                            format!(
                                "transfer quantity exceeds source quantity for RWA {}",
                                source_lot.id()
                            )
                            .into(),
                        )
                    })?;
            let child_id = state_transaction
                .next_generated_rwa_id(source_lot.id().domain(), TransferRwa::WIRE_ID)?;
            if state_transaction.world.rwa(&child_id).is_ok() {
                return Err(RepetitionError {
                    instruction: InstructionType::Custom,
                    id: IdBox::RwaId(child_id),
                }
                .into());
            }
            {
                let rwa_mut = state_transaction.world.rwa_mut(&rwa)?;
                rwa_mut.quantity = new_quantity;
            }
            let child = child_from_parent(
                &source_lot,
                child_id.clone(),
                quantity.clone(),
                destination.clone(),
            );
            let (id, value) = child.clone().into_key_value();
            state_transaction.world.insert_rwa_entry(id, value);
            state_transaction.world.emit_events([
                DomainEvent::Rwa(RwaEvent::Created(child)),
                DomainEvent::Rwa(RwaEvent::Split(RwaSplit {
                    source: rwa,
                    child: child_id,
                    quantity,
                    new_owner: destination,
                })),
            ]);
            Ok(())
        }
    }
    impl Execute for MergeRwas {
        #[metrics(+"merge_rwas")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            if self.parents.is_empty() {
                return Err(Error::InvariantViolation(
                    "merge requires at least one parent lot".into(),
                ));
            }
            let mut merged_quantity = Quantity::zero();
            let mut domain: Option<DomainId> = None;
            let mut spec: Option<NumericSpec> = None;
            let mut seen = BTreeSet::new();
            for parent in &self.parents {
                if !seen.insert(parent.rwa().clone()) {
                    return Err(Error::InvariantViolation(
                        "merge parents must not contain duplicates".into(),
                    ));
                }
                ensure_positive_quantity(parent.quantity(), "merge parent")?;
                let source_lot = load_rwa(&state_transaction.world, parent.rwa())?;
                let is_controller = ensure_owner_or_controller(
                    &state_transaction.world,
                    authority,
                    &source_lot,
                    "merge",
                )?;
                if source_lot.is_frozen && !is_controller {
                    return Err(Error::InvariantViolation(
                        format!("RWA {} is frozen", source_lot.id()).into(),
                    ));
                }
                let lot_domain = source_lot.id().domain().clone();
                match &domain {
                    Some(existing) if existing != &lot_domain => {
                        return Err(Error::InvariantViolation(
                            "all merge parents must belong to the same domain".into(),
                        ));
                    }
                    None => domain = Some(lot_domain),
                    Some(_) => {}
                }
                match spec {
                    Some(existing) if existing != source_lot.spec => {
                        return Err(Error::InvariantViolation(
                            "all merge parents must use the same numeric spec".into(),
                        ));
                    }
                    None => spec = Some(source_lot.spec.clone()),
                    Some(_) => {}
                }
                ensure_quantity_matches_spec(
                    source_lot.spec.clone(),
                    parent.quantity(),
                    "merge parent",
                )?;
                let available = source_lot.available_quantity().ok_or_else(|| {
                    Error::InvariantViolation(
                        format!(
                            "RWA {} has invalid held quantity accounting",
                            source_lot.id()
                        )
                        .into(),
                    )
                })?;
                ensure_quantity_available(
                    &available,
                    parent.quantity(),
                    format!(
                        "merge quantity exceeds available quantity for parent RWA {}",
                        source_lot.id()
                    ),
                )?;
                merged_quantity = merged_quantity
                    .checked_add(parent.quantity())
                    .map_err(|_| Error::InvariantViolation("merge quantity overflow".into()))?;
            }
            let domain = domain.expect("merge parent domain");
            let spec = spec.expect("merge parent spec");
            ensure_quantity_matches_spec(spec, &merged_quantity, "merge child")?;
            let _ = state_transaction.world.domain(&domain)?;
            let child_id = state_transaction.next_generated_rwa_id(&domain, MergeRwas::WIRE_ID)?;
            if state_transaction.world.rwa(&child_id).is_ok() {
                return Err(RepetitionError {
                    instruction: InstructionType::Custom,
                    id: IdBox::RwaId(child_id),
                }
                .into());
            }
            for parent in &self.parents {
                let lot = load_rwa(&state_transaction.world, parent.rwa())?;
                let new_quantity = lot
                    .quantity
                    .clone()
                    .checked_sub(parent.quantity())
                    .map_err(|_| {
                        Error::InvariantViolation(
                            format!(
                                "merge quantity exceeds source quantity for RWA {}",
                                lot.id()
                            )
                            .into(),
                        )
                    })?;
                let lot_mut = state_transaction.world.rwa_mut(parent.rwa())?;
                lot_mut.quantity = new_quantity;
            }
            let child = child_from_merge(
                child_id.clone(),
                authority.clone(),
                merged_quantity,
                spec,
                self.primary_reference,
                self.status,
                self.metadata,
                self.parents.clone(),
            );
            let (id, value) = child.clone().into_key_value();
            state_transaction.world.insert_rwa_entry(id, value);
            state_transaction.world.emit_events([
                DomainEvent::Rwa(RwaEvent::Created(child)),
                DomainEvent::Rwa(RwaEvent::Merged(RwaMerged {
                    child: child_id,
                    parents: self.parents,
                })),
            ]);
            Ok(())
        }
    }
    impl Execute for RedeemRwa {
        #[metrics(+"redeem_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            ensure_positive_quantity(&self.quantity, "redeem")?;
            let rwa = load_rwa(&state_transaction.world, &self.rwa)?;
            let is_controller =
                ensure_owner_or_controller(&state_transaction.world, authority, &rwa, "redeem")?;
            if rwa.is_frozen && !is_controller {
                return Err(Error::InvariantViolation(
                    format!("RWA {} is frozen", rwa.id()).into(),
                ));
            }
            if !rwa.controls().redeem_enabled {
                return Err(Error::InvariantViolation(
                    format!("redeem is disabled for RWA {}", rwa.id()).into(),
                ));
            }
            ensure_quantity_matches_spec(rwa.spec.clone(), &self.quantity, "redeem")?;
            let available = rwa.available_quantity().ok_or_else(|| {
                Error::InvariantViolation(
                    format!("RWA {} has invalid held quantity accounting", rwa.id()).into(),
                )
            })?;
            ensure_quantity_available(
                &available,
                &self.quantity,
                format!(
                    "redeem quantity exceeds available quantity for RWA {}",
                    rwa.id()
                ),
            )?;
            let new_quantity = rwa
                .quantity
                .clone()
                .checked_sub(&self.quantity)
                .map_err(|_| {
                    Error::InvariantViolation(
                        format!(
                            "redeem quantity exceeds source quantity for RWA {}",
                            rwa.id()
                        )
                        .into(),
                    )
                })?;
            let rwa_mut = state_transaction.world.rwa_mut(&self.rwa)?;
            rwa_mut.quantity = new_quantity;
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Rwa(RwaEvent::Redeemed(
                    RwaQuantityChanged {
                        rwa: self.rwa,
                        quantity: self.quantity,
                    },
                ))));
            Ok(())
        }
    }
    impl Execute for FreezeRwa {
        #[metrics(+"freeze_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let rwa_id = self.rwa;
            let rwa = load_rwa(&state_transaction.world, &rwa_id)?;
            ensure_controller_enabled(
                &state_transaction.world,
                authority,
                &rwa,
                rwa.controls().freeze_enabled,
                "freeze",
            )?;
            let changed = {
                let rwa_mut = state_transaction.world.rwa_mut(&rwa_id)?;
                if rwa_mut.is_frozen {
                    false
                } else {
                    rwa_mut.is_frozen = true;
                    true
                }
            };
            if changed {
                state_transaction
                    .world
                    .replace_rwa_frozen_index(&rwa_id, false, true);
                state_transaction
                    .world
                    .emit_events(Some(DomainEvent::Rwa(RwaEvent::Frozen(rwa_id))));
            }
            Ok(())
        }
    }
    impl Execute for UnfreezeRwa {
        #[metrics(+"unfreeze_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let rwa_id = self.rwa;
            let rwa = load_rwa(&state_transaction.world, &rwa_id)?;
            ensure_controller_enabled(
                &state_transaction.world,
                authority,
                &rwa,
                rwa.controls().freeze_enabled,
                "unfreeze",
            )?;
            let changed = {
                let rwa_mut = state_transaction.world.rwa_mut(&rwa_id)?;
                if rwa_mut.is_frozen {
                    rwa_mut.is_frozen = false;
                    true
                } else {
                    false
                }
            };
            if changed {
                state_transaction
                    .world
                    .replace_rwa_frozen_index(&rwa_id, true, false);
                state_transaction
                    .world
                    .emit_events(Some(DomainEvent::Rwa(RwaEvent::Unfrozen(rwa_id))));
            }
            Ok(())
        }
    }
    impl Execute for HoldRwa {
        #[metrics(+"hold_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            ensure_positive_quantity(&self.quantity, "hold")?;
            let rwa = load_rwa(&state_transaction.world, &self.rwa)?;
            ensure_controller_enabled(
                &state_transaction.world,
                authority,
                &rwa,
                rwa.controls().hold_enabled,
                "hold",
            )?;
            ensure_quantity_matches_spec(rwa.spec.clone(), &self.quantity, "hold")?;
            let new_held = rwa
                .held_quantity
                .clone()
                .checked_add(&self.quantity)
                .map_err(|_| Error::InvariantViolation("hold quantity overflow".into()))?;
            let available_after = rwa.quantity.clone().checked_sub(&new_held).map_err(|_| {
                Error::InvariantViolation(
                    format!("hold quantity exceeds total quantity for RWA {}", rwa.id()).into(),
                )
            })?;
            let _ = available_after;
            let rwa_mut = state_transaction.world.rwa_mut(&self.rwa)?;
            rwa_mut.held_quantity = new_held;
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Rwa(RwaEvent::Held(RwaHoldChanged {
                    rwa: self.rwa,
                    quantity: self.quantity,
                }))));
            Ok(())
        }
    }
    impl Execute for ReleaseRwa {
        #[metrics(+"release_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            ensure_positive_quantity(&self.quantity, "release")?;
            let rwa = load_rwa(&state_transaction.world, &self.rwa)?;
            ensure_controller_enabled(
                &state_transaction.world,
                authority,
                &rwa,
                rwa.controls().hold_enabled,
                "release",
            )?;
            ensure_quantity_matches_spec(rwa.spec.clone(), &self.quantity, "release")?;
            let new_held = rwa
                .held_quantity
                .clone()
                .checked_sub(&self.quantity)
                .map_err(|_| {
                    Error::InvariantViolation(
                        format!(
                            "release quantity exceeds held quantity for RWA {}",
                            rwa.id()
                        )
                        .into(),
                    )
                })?;
            let rwa_mut = state_transaction.world.rwa_mut(&self.rwa)?;
            rwa_mut.held_quantity = new_held;
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Rwa(RwaEvent::Released(RwaHoldChanged {
                    rwa: self.rwa,
                    quantity: self.quantity,
                }))));
            Ok(())
        }
    }
    impl Execute for ForceTransferRwa {
        #[metrics(+"force_transfer_rwa")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            ensure_positive_quantity(&self.quantity, "force transfer")?;
            let _created =
                ensure_receiving_account(authority, &self.destination, None, state_transaction)?;
            let source_lot = load_rwa(&state_transaction.world, &self.rwa)?;
            ensure_controller_enabled(
                &state_transaction.world,
                authority,
                &source_lot,
                source_lot.controls().force_transfer_enabled,
                "force transfer",
            )?;
            ensure_quantity_matches_spec(
                source_lot.spec.clone(),
                &self.quantity,
                "force transfer",
            )?;
            let available = source_lot.available_quantity().ok_or_else(|| {
                Error::InvariantViolation(
                    format!(
                        "RWA {} has invalid held quantity accounting",
                        source_lot.id()
                    )
                    .into(),
                )
            })?;
            ensure_quantity_available(
                &available,
                &self.quantity,
                format!(
                    "force transfer quantity exceeds available quantity for RWA {}",
                    source_lot.id()
                ),
            )?;
            if self.quantity == source_lot.quantity && source_lot.held_quantity.is_zero() {
                {
                    let rwa_mut = state_transaction.world.rwa_mut(&self.rwa)?;
                    rwa_mut.owned_by = self.destination.clone();
                }
                state_transaction.world.replace_rwa_owner_index(
                    &self.rwa,
                    &source_lot.owned_by,
                    &self.destination,
                );
                state_transaction.world.emit_events(Some(DomainEvent::Rwa(
                    RwaEvent::OwnerChanged(RwaOwnerChanged {
                        rwa: self.rwa,
                        new_owner: self.destination,
                    }),
                )));
                return Ok(());
            }
            let new_quantity = source_lot
                .quantity
                .clone()
                .checked_sub(&self.quantity)
                .map_err(|_| {
                    Error::InvariantViolation(
                        format!(
                            "force transfer quantity exceeds source quantity for RWA {}",
                            source_lot.id()
                        )
                        .into(),
                    )
                })?;
            let child_id = state_transaction
                .next_generated_rwa_id(source_lot.id().domain(), ForceTransferRwa::WIRE_ID)?;
            if state_transaction.world.rwa(&child_id).is_ok() {
                return Err(RepetitionError {
                    instruction: InstructionType::Custom,
                    id: IdBox::RwaId(child_id),
                }
                .into());
            }
            {
                let rwa_mut = state_transaction.world.rwa_mut(&self.rwa)?;
                rwa_mut.quantity = new_quantity;
            }
            let child = child_from_parent(
                &source_lot,
                child_id.clone(),
                self.quantity.clone(),
                self.destination.clone(),
            );
            let (id, value) = child.clone().into_key_value();
            state_transaction.world.insert_rwa_entry(id, value);
            state_transaction.world.emit_events([
                DomainEvent::Rwa(RwaEvent::Created(child)),
                DomainEvent::Rwa(RwaEvent::ForceTransferred(RwaSplit {
                    source: self.rwa,
                    child: child_id,
                    quantity: self.quantity,
                    new_owner: self.destination,
                })),
            ]);
            Ok(())
        }
    }
    impl Execute for SetRwaControls {
        #[metrics(+"set_rwa_controls")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let rwa = load_rwa(&state_transaction.world, &self.rwa)?;
            let _ = ensure_owner_or_controller(
                &state_transaction.world,
                authority,
                &rwa,
                "set controls",
            )?;
            let rwa_mut = state_transaction.world.rwa_mut(&self.rwa)?;
            rwa_mut.controls = self.controls.clone();
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Rwa(RwaEvent::ControlsChanged(
                    RwaControlsChanged {
                        rwa: self.rwa,
                        controls: self.controls,
                    },
                ))));
            Ok(())
        }
    }
    impl Execute for SetKeyValue<Rwa> {
        #[metrics(+"set_rwa_key_value")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let SetKeyValue {
                object: rwa_id,
                key,
                value,
            } = self;
            crate::smartcontracts::limits::enforce_json_size(
                state_transaction,
                &value,
                "max_metadata_value_bytes",
                crate::smartcontracts::limits::DEFAULT_JSON_LIMIT,
            )?;
            let rwa = load_rwa(&state_transaction.world, &rwa_id)?;
            let is_controller = ensure_owner_or_controller(
                &state_transaction.world,
                authority,
                &rwa,
                "set metadata",
            )?;
            if rwa.is_frozen && !is_controller {
                return Err(Error::InvariantViolation(
                    format!("RWA {} is frozen", rwa.id()).into(),
                ));
            }
            state_transaction
                .world
                .rwa_mut(&rwa_id)?
                .metadata
                .insert(key.clone(), value.clone());
            state_transaction.world.emit_events(Some(DomainEvent::Rwa(
                RwaEvent::MetadataInserted(MetadataChanged {
                    target: rwa_id,
                    key,
                    value,
                }),
            )));
            Ok(())
        }
    }
    impl Execute for RemoveKeyValue<Rwa> {
        #[metrics(+"remove_rwa_key_value")]
        fn execute(
            self,
            authority: &AccountId,
            state_transaction: &mut StateTransaction<'_, '_>,
        ) -> Result<(), Error> {
            let rwa = load_rwa(&state_transaction.world, self.object())?;
            let is_controller = ensure_owner_or_controller(
                &state_transaction.world,
                authority,
                &rwa,
                "remove metadata",
            )?;
            if rwa.is_frozen && !is_controller {
                return Err(Error::InvariantViolation(
                    format!("RWA {} is frozen", rwa.id()).into(),
                ));
            }
            let rwa_id = self.object().clone();
            let value = state_transaction
                .world
                .rwa_mut(&rwa_id)?
                .metadata
                .remove(self.key().as_ref())
                .ok_or_else(|| FindError::MetadataKey(self.key().clone()))?;
            state_transaction
                .world
                .emit_events(Some(DomainEvent::Rwa(RwaEvent::MetadataRemoved(
                    MetadataChanged {
                        target: rwa_id,
                        key: self.key().clone(),
                        value,
                    },
                ))));
            Ok(())
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            block::ValidBlock,
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use core::num::NonZeroU64;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_primitives::json::Json;
        use iroha_test_samples::ALICE_ID;
        fn checked_keypair() -> KeyPair {
            KeyPair::try_random().expect("RWA ISI fixture key generation should succeed")
        }
        fn checked_account_id() -> AccountId {
            AccountId::new(checked_keypair().public_key().clone())
        }
        #[test]
        fn checked_keypair_preserves_default_algorithm() {
            assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        }
        fn new_dummy_block() -> crate::block::CommittedBlock {
            let (leader_public_key, leader_private_key) = checked_keypair().into_parts();
            let peer_id = iroha_model_base::peer::PeerId::new(leader_public_key);
            let topology = crate::sumeragi::network_topology::Topology::new(vec![peer_id]);
            ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
                h.set_height(NonZeroU64::new(1).unwrap());
            })
            .commit(&topology, crate::block::reserve_block_for_tests())
            .unpack(|_| {})
            .unwrap()
        }
        fn test_state() -> State {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            State::new(World::default(), kura, query_handle)
        }
        fn seed_domain_name_lease(
            world: &mut crate::state::WorldTransaction<'_, '_>,
            owner: &AccountId,
            domain_id: &DomainId,
        ) {
            let selector = crate::sns::selector_for_domain(domain_id).expect("selector");
            let address =
                iroha_data_model::account::AccountAddress::from_account_id(owner).expect("address");
            let record = iroha_data_model::sns::NameRecordV1::new(
                selector.clone(),
                owner.clone(),
                vec![iroha_data_model::sns::NameControllerV1::account(&address)],
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                Metadata::default(),
            );
            world.smart_contract_state_mut_for_testing().insert(
                crate::sns::record_storage_key(&selector),
                norito::codec::Encode::encode(&record),
            );
        }
        fn register_domain_and_accounts(
            stx: &mut StateTransaction<'_, '_>,
            domain_id: &DomainId,
            accounts: &[AccountId],
        ) {
            if stx.tx_call_hash.is_none() {
                stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
                    [0xA5; iroha_crypto::Hash::LENGTH],
                ));
            }
            seed_domain_name_lease(&mut stx.world, &ALICE_ID, domain_id);
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, stx)
                .expect("register domain");
            for account in accounts {
                Register::account(Account::new(account.clone()))
                    .execute(&ALICE_ID, stx)
                    .expect("register account");
            }
        }
        #[test]
        fn register_rwa_rejects_missing_domain() {
            let state = test_state();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let missing_domain: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
            let err = RegisterRwa {
                rwa: NewRwa::new(
                    missing_domain.clone(),
                    "5".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/1".to_owned(),
                    None,
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&ALICE_ID, &mut stx)
            .expect_err("missing domain must fail");
            assert!(matches!(err, Error::Find(FindError::Domain(ref id)) if id == &missing_domain));
        }
        #[test]
        fn partial_transfer_splits_rwa_lot() {
            let state = test_state();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            let owner = ALICE_ID.clone();
            let recipient = checked_account_id();
            register_domain_and_accounts(&mut stx, &domain_id, &[owner.clone(), recipient.clone()]);
            RegisterRwa {
                rwa: NewRwa::new(
                    domain_id.clone(),
                    "10".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/lot-1".to_owned(),
                    Some("vaulted".parse().unwrap()),
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            let source_id = stx
                .world
                .rwas
                .iter()
                .next()
                .map(|(id, _)| id.clone())
                .expect("registered rwa");
            TransferRwa {
                source: owner.clone(),
                rwa: source_id.clone(),
                quantity: "4".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            let lots: Vec<_> = stx
                .world
                .rwas
                .iter()
                .map(|(id, value)| (id.clone(), value.clone().into_inner()))
                .collect();
            assert_eq!(lots.len(), 2, "partial transfer should create a child lot");
            let source = stx.world.rwa(&source_id).map(authoritative_rwa).unwrap();
            assert_eq!(source.quantity, "6".parse::<Quantity>().unwrap());
            assert_eq!(source.owned_by, owner);
            let child = lots
                .into_iter()
                .find(|(id, _)| id != &source_id)
                .map(|(id, data)| Rwa {
                    id,
                    quantity: data.quantity,
                    spec: data.spec,
                    primary_reference: data.primary_reference,
                    status: data.status,
                    metadata: data.metadata,
                    parents: data.parents,
                    controls: data.controls,
                    owned_by: data.owned_by,
                    is_frozen: data.is_frozen,
                    held_quantity: data.held_quantity,
                })
                .expect("child lot");
            assert_eq!(child.quantity, "4".parse::<Quantity>().unwrap());
            assert_eq!(child.owned_by, recipient);
            assert_eq!(child.parents.len(), 1);
            assert_eq!(child.parents[0].rwa(), &source_id);
            assert!(
                stx.world
                    .rwas_by_owner
                    .get(&owner)
                    .is_some_and(|ids| ids.contains(&source_id)),
                "source lot should remain indexed under the original owner",
            );
            assert!(
                stx.world
                    .rwas_by_owner
                    .get(&recipient)
                    .is_some_and(|ids| ids.contains(child.id())),
                "child lot should be indexed under the recipient",
            );
        }
        #[test]
        fn full_transfer_updates_owner_in_place() {
            let state = test_state();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            let owner = ALICE_ID.clone();
            let recipient = checked_account_id();
            register_domain_and_accounts(&mut stx, &domain_id, &[owner.clone(), recipient.clone()]);
            RegisterRwa {
                rwa: NewRwa::new(
                    domain_id.clone(),
                    "3".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/lot-2".to_owned(),
                    None,
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            let rwa_id = stx.world.rwas.iter().next().unwrap().0.clone();
            ForceTransferRwa {
                rwa: rwa_id.clone(),
                quantity: "3".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&owner, &mut stx)
            .expect_err("force transfer should require controller");
            TransferRwa {
                source: owner.clone(),
                rwa: rwa_id.clone(),
                quantity: "3".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            assert_eq!(stx.world.rwas.iter().count(), 1);
            let rwa = stx.world.rwa(&rwa_id).map(authoritative_rwa).unwrap();
            assert_eq!(rwa.owned_by, recipient);
            assert_eq!(rwa.quantity, "3".parse::<Quantity>().unwrap());
            assert!(
                !stx.world
                    .rwas_by_owner
                    .get(&owner)
                    .is_some_and(|ids| ids.contains(&rwa_id)),
                "full transfer should remove the lot from the previous owner index",
            );
            assert!(
                stx.world
                    .rwas_by_owner
                    .get(&recipient)
                    .is_some_and(|ids| ids.contains(&rwa_id)),
                "full transfer should add the lot to the recipient owner index",
            );
        }
        #[test]
        fn merge_and_redeem_rwas() {
            let state = test_state();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            let owner = ALICE_ID.clone();
            register_domain_and_accounts(&mut stx, &domain_id, std::slice::from_ref(&owner));
            for lot in ["5", "7"] {
                RegisterRwa {
                    rwa: NewRwa::new(
                        domain_id.clone(),
                        lot.parse::<Quantity>().unwrap(),
                        NumericSpec::integer(),
                        format!("https://example.test/rwa/{lot}"),
                        None,
                        Metadata::default(),
                        Vec::new(),
                        RwaControlPolicy::default(),
                    ),
                }
                .execute(&owner, &mut stx)
                .unwrap();
            }
            let parent_ids: Vec<_> = stx.world.rwas.iter().map(|(id, _)| id.clone()).collect();
            MergeRwas {
                parents: vec![
                    RwaParentRef::new(parent_ids[0].clone(), "2".parse::<Quantity>().unwrap()),
                    RwaParentRef::new(parent_ids[1].clone(), "3".parse::<Quantity>().unwrap()),
                ],
                primary_reference: "https://example.test/rwa/merged".to_owned(),
                status: Some("refined".parse().unwrap()),
                metadata: Metadata::default(),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            assert_eq!(
                stx.world
                    .rwa(&parent_ids[0])
                    .map(authoritative_rwa)
                    .unwrap()
                    .quantity,
                "3".parse::<Quantity>().unwrap()
            );
            assert_eq!(
                stx.world
                    .rwa(&parent_ids[1])
                    .map(authoritative_rwa)
                    .unwrap()
                    .quantity,
                "4".parse::<Quantity>().unwrap()
            );
            let merged_id = stx
                .world
                .rwas
                .iter()
                .map(|(id, _)| id.clone())
                .find(|id| !parent_ids.contains(id))
                .unwrap();
            let err = RedeemRwa {
                rwa: merged_id.clone(),
                quantity: "1".parse::<Quantity>().unwrap(),
            }
            .execute(&owner, &mut stx)
            .expect_err("redeem disabled by default");
            assert!(
                err.to_string().contains("redeem is disabled"),
                "unexpected redeem error: {err}"
            );
            SetRwaControls {
                rwa: merged_id.clone(),
                controls: RwaControlPolicy {
                    redeem_enabled: true,
                    ..RwaControlPolicy::default()
                },
            }
            .execute(&owner, &mut stx)
            .unwrap();
            RedeemRwa {
                rwa: merged_id.clone(),
                quantity: "1".parse::<Quantity>().unwrap(),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            assert_eq!(
                stx.world
                    .rwa(&merged_id)
                    .map(authoritative_rwa)
                    .unwrap()
                    .quantity,
                "4".parse::<Quantity>().unwrap()
            );
        }
        #[test]
        fn repeated_register_generates_distinct_lot_ids() {
            let state = test_state();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            let owner = ALICE_ID.clone();
            register_domain_and_accounts(&mut stx, &domain_id, std::slice::from_ref(&owner));
            let new_rwa = NewRwa::new(
                domain_id,
                "5".parse::<Quantity>().unwrap(),
                NumericSpec::integer(),
                "https://example.test/rwa/repeated".to_owned(),
                None,
                Metadata::default(),
                Vec::new(),
                RwaControlPolicy::default(),
            );
            RegisterRwa {
                rwa: new_rwa.clone(),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            RegisterRwa { rwa: new_rwa }
                .execute(&owner, &mut stx)
                .unwrap();
            let ids: Vec<_> = stx.world.rwas.iter().map(|(id, _)| id.clone()).collect();
            assert_eq!(ids.len(), 2);
            assert_ne!(ids[0], ids[1]);
        }
        #[test]
        fn repeated_partial_transfers_generate_distinct_child_ids() {
            let state = test_state();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            let owner = ALICE_ID.clone();
            let recipient = checked_account_id();
            register_domain_and_accounts(&mut stx, &domain_id, &[owner.clone(), recipient.clone()]);
            RegisterRwa {
                rwa: NewRwa::new(
                    domain_id,
                    "10".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/transfer-seq".to_owned(),
                    None,
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            let source_id = stx.world.rwas.iter().next().unwrap().0.clone();
            TransferRwa {
                source: owner.clone(),
                rwa: source_id.clone(),
                quantity: "2".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            TransferRwa {
                source: owner.clone(),
                rwa: source_id.clone(),
                quantity: "2".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            let child_ids: Vec<_> = stx
                .world
                .rwas
                .iter()
                .map(|(id, _)| id.clone())
                .filter(|id| id != &source_id)
                .collect();
            assert_eq!(child_ids.len(), 2);
            assert_ne!(child_ids[0], child_ids[1]);
        }
        #[test]
        fn controls_gate_freeze_hold_and_force_transfer() {
            let state = test_state();
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            let owner = ALICE_ID.clone();
            let controller = checked_account_id();
            let recipient = checked_account_id();
            register_domain_and_accounts(
                &mut stx,
                &domain_id,
                &[owner.clone(), controller.clone(), recipient.clone()],
            );
            RegisterRwa {
                rwa: NewRwa::new(
                    domain_id,
                    "8".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/controlled".to_owned(),
                    None,
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy {
                        controller_accounts: vec![controller.clone()],
                        freeze_enabled: true,
                        hold_enabled: true,
                        force_transfer_enabled: true,
                        ..RwaControlPolicy::default()
                    },
                ),
            }
            .execute(&owner, &mut stx)
            .unwrap();
            let rwa_id = stx.world.rwas.iter().next().unwrap().0.clone();
            HoldRwa {
                rwa: rwa_id.clone(),
                quantity: "3".parse::<Quantity>().unwrap(),
            }
            .execute(&controller, &mut stx)
            .unwrap();
            let err = TransferRwa {
                source: owner.clone(),
                rwa: rwa_id.clone(),
                quantity: "6".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&owner, &mut stx)
            .expect_err("held quantity must reduce availability");
            assert!(err.to_string().contains("available quantity"));
            FreezeRwa {
                rwa: rwa_id.clone(),
            }
            .execute(&controller, &mut stx)
            .unwrap();
            let err = SetKeyValue::rwa(rwa_id.clone(), "grade".parse().unwrap(), Json::from("A"))
                .execute(&owner, &mut stx)
                .expect_err("frozen RWA must block owner metadata edits");
            assert!(err.to_string().contains("frozen"));
            ForceTransferRwa {
                rwa: rwa_id.clone(),
                quantity: "2".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&controller, &mut stx)
            .unwrap();
            let child_count = stx.world.rwas.iter().count();
            assert_eq!(
                child_count, 2,
                "force transfer should split into a child lot"
            );
        }
    }
}
/// RWA-related query implementations.
pub mod query {
    use super::*;
    use crate::smartcontracts::isi::query::json_predicate::{
        cached_predicate_json_value, parse_domain_predicate_value, predicate_value_at_path,
        predicate_value_equals_str, predicate_values_contain_str,
    };
    use crate::{
        smartcontracts::ValidQuery,
        state::{StateReadOnly, WorldReadOnly},
    };
    use eyre::Result;
    use iroha_data_model::query::{
        dsl::{CompoundPredicate, EvaluatePredicate},
        error::QueryExecutionFail as Error,
        json::PredicateJson,
    };
    use iroha_data_model::rwa::RwaEntry;
    use iroha_model_base::domain::DomainId;
    use norito::json::Value;
    use std::collections::BTreeSet;
    #[derive(Debug, Default, Clone)]
    struct RwaPredicateView {
        ids: BTreeSet<RwaId>,
        owners: BTreeSet<AccountId>,
        domains: BTreeSet<DomainId>,
        statuses: BTreeSet<Option<Name>>,
        frozen: BTreeSet<bool>,
    }
    impl RwaPredicateView {
        fn from_predicate(predicate: &CompoundPredicate<Rwa>) -> Self {
            let mut view = Self::default();
            let Some(raw) = predicate.json_payload() else {
                return view;
            };
            let Some(parsed) =
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution(raw)
            else {
                return view;
            };
            view.ingest_predicate(parsed);
            view
        }
        fn ingest_predicate(&mut self, predicate: PredicateJson) {
            for condition in predicate.equals {
                self.push_field_value(&condition.field, &condition.value);
            }
            for membership in predicate.r#in {
                for value in membership.values {
                    self.push_field_value(&membership.field, &value);
                }
            }
        }
        fn push_field_value(&mut self, field: &str, value: &Value) {
            if matches!(field, "frozen" | "is_frozen")
                && let Some(is_frozen) = Self::value_as_bool(value)
            {
                self.frozen.insert(is_frozen);
            }
            if field == "status" && value.is_null() {
                self.statuses.insert(None);
            }
            let Some(raw) = Self::value_as_str(value) else {
                return;
            };
            match field {
                "id" => {
                    if let Ok(rwa_id) = raw.parse::<RwaId>() {
                        self.domains.insert(rwa_id.domain().clone());
                        self.ids.insert(rwa_id);
                    }
                }
                "owner" | "owned_by" | "account" | "account_id" => {
                    if let Ok(account_id) = AccountId::parse_encoded(raw) {
                        self.owners.insert(account_id.subject_id());
                    }
                }
                "domain" | "id.domain" => {
                    if let Some(domain_id) = parse_domain_predicate_value(raw) {
                        self.domains.insert(domain_id);
                    }
                }
                "status" => {
                    if let Ok(status) = raw.parse::<Name>() {
                        self.statuses.insert(Some(status));
                    }
                }
                _ => {}
            }
        }
        fn value_as_str(value: &Value) -> Option<&str> {
            if let Value::String(raw) = value {
                Some(raw.as_str())
            } else {
                None
            }
        }
        fn value_as_bool(value: &Value) -> Option<bool> {
            if let Value::Bool(value) = value {
                Some(*value)
            } else {
                None
            }
        }
        fn intersect_candidate_ids(
            best: &mut Option<BTreeSet<RwaId>>,
            candidates: BTreeSet<RwaId>,
        ) {
            if let Some(selected) = best {
                selected.retain(|rwa_id| candidates.contains(rwa_id));
            } else {
                *best = Some(candidates);
            }
        }
        fn indexed_candidate_ids(&self, world: &impl WorldReadOnly) -> Option<BTreeSet<RwaId>> {
            let mut selected = None;
            if !self.ids.is_empty() {
                Self::intersect_candidate_ids(&mut selected, self.ids.iter().cloned().collect());
            }
            if !self.owners.is_empty() {
                let candidates = self
                    .owners
                    .iter()
                    .flat_map(|owner| world.rwas_in_account_iter(owner))
                    .map(|entry| entry.id().clone())
                    .collect();
                Self::intersect_candidate_ids(&mut selected, candidates);
            }
            if !self.domains.is_empty() {
                let candidates = self
                    .domains
                    .iter()
                    .flat_map(|domain| world.rwas_in_domain_iter(domain))
                    .map(|entry| entry.id().clone())
                    .collect();
                Self::intersect_candidate_ids(&mut selected, candidates);
            }
            if !self.statuses.is_empty() {
                let candidates = self
                    .statuses
                    .iter()
                    .flat_map(|status| world.rwas_by_status_iter(status))
                    .map(|entry| entry.id().clone())
                    .collect();
                Self::intersect_candidate_ids(&mut selected, candidates);
            }
            if !self.frozen.is_empty() {
                let candidates = self
                    .frozen
                    .iter()
                    .flat_map(|is_frozen| world.rwas_by_frozen_iter(*is_frozen))
                    .map(|entry| entry.id().clone())
                    .collect();
                Self::intersect_candidate_ids(&mut selected, candidates);
            }
            selected
        }
    }
    fn rwa_alias_values(rwa: &Rwa, field: &str) -> Vec<String> {
        match field {
            "id" => vec![rwa.id().to_string()],
            "owner" | "owned_by" | "account" | "account_id" => vec![rwa.owned_by().to_string()],
            "domain" | "id.domain" => {
                let domain = rwa.id().domain();
                let canonical = domain.to_string();
                let shorthand = domain.name().to_string();
                if canonical == shorthand {
                    vec![canonical]
                } else {
                    vec![canonical, shorthand]
                }
            }
            _ => Vec::new(),
        }
    }
    fn predicate_value_matches_bool(value: &Value, expected: bool) -> bool {
        match value {
            Value::Bool(raw) => *raw == expected,
            Value::String(raw) => raw == &expected.to_string(),
            _ => false,
        }
    }
    fn predicate_value_matches_status(value: &Value, expected: Option<&Name>) -> bool {
        match (value, expected) {
            (Value::Null, None) => true,
            (Value::String(raw), Some(status)) => raw == &status.to_string(),
            _ => false,
        }
    }
    fn predicate_matches_rwa(predicate: &PredicateJson, rwa: &Rwa) -> bool {
        let mut rwa_json = None;
        for cond in &predicate.equals {
            if matches!(cond.field.as_str(), "frozen" | "is_frozen") {
                if predicate_value_matches_bool(&cond.value, rwa.is_frozen) {
                    continue;
                }
                return false;
            }
            if cond.field == "status" {
                if predicate_value_matches_status(&cond.value, rwa.status.as_ref()) {
                    continue;
                }
                return false;
            }
            let aliases = rwa_alias_values(rwa, &cond.field);
            if !aliases.is_empty() {
                if !aliases
                    .iter()
                    .any(|alias| predicate_value_equals_str(&cond.value, alias))
                {
                    return false;
                }
                continue;
            }
            let Some(value) = cached_predicate_json_value(&mut rwa_json, rwa) else {
                continue;
            };
            let Some(actual) = predicate_value_at_path(value, &cond.field) else {
                return false;
            };
            if actual != &cond.value {
                return false;
            }
        }
        for cond in &predicate.r#in {
            if matches!(cond.field.as_str(), "frozen" | "is_frozen") {
                if cond
                    .values
                    .iter()
                    .any(|value| predicate_value_matches_bool(value, rwa.is_frozen))
                {
                    continue;
                }
                return false;
            }
            if cond.field == "status" {
                if cond
                    .values
                    .iter()
                    .any(|value| predicate_value_matches_status(value, rwa.status.as_ref()))
                {
                    continue;
                }
                return false;
            }
            let aliases = rwa_alias_values(rwa, &cond.field);
            if !aliases.is_empty() {
                if !aliases
                    .iter()
                    .any(|alias| predicate_values_contain_str(&cond.values, alias))
                {
                    return false;
                }
                continue;
            }
            let Some(value) = cached_predicate_json_value(&mut rwa_json, rwa) else {
                continue;
            };
            let Some(actual) = predicate_value_at_path(value, &cond.field) else {
                return false;
            };
            if !cond.values.iter().any(|candidate| candidate == actual) {
                return false;
            }
        }
        for field in &predicate.exists {
            if matches!(field.as_str(), "frozen" | "is_frozen") {
                continue;
            }
            if field == "status" && rwa.status.is_some() {
                continue;
            }
            if !rwa_alias_values(rwa, field).is_empty() {
                continue;
            }
            let Some(value) = cached_predicate_json_value(&mut rwa_json, rwa) else {
                continue;
            };
            let Some(actual) = predicate_value_at_path(value, field) else {
                return false;
            };
            if actual.is_null() {
                return false;
            }
        }
        true
    }
    fn entry_to_rwa(entry: RwaEntry<'_>) -> Rwa {
        let value = entry.value().clone().into_inner();
        Rwa {
            id: entry.id().clone(),
            quantity: value.quantity,
            spec: value.spec,
            primary_reference: value.primary_reference,
            status: value.status,
            metadata: value.metadata,
            parents: value.parents,
            controls: value.controls,
            owned_by: value.owned_by,
            is_frozen: value.is_frozen,
            held_quantity: value.held_quantity,
        }
    }
    impl ValidQuery for FindRwas {
        #[metrics(+"find_rwas")]
        fn execute(
            self,
            filter: CompoundPredicate<Rwa>,
            state_ro: &impl StateReadOnly,
        ) -> Result<impl Iterator<Item = Rwa>, Error> {
            let world = state_ro.world();
            let predicate_view = RwaPredicateView::from_predicate(&filter);
            let predicate_json = filter.json_payload().and_then(
                iroha_data_model::query::json::predicate_json_candidate_plan_for_execution,
            );
            let iter: Box<dyn Iterator<Item = Rwa> + '_> =
                if let Some(candidate_ids) = predicate_view.indexed_candidate_ids(world) {
                    Box::new(
                        candidate_ids
                            .into_iter()
                            .filter_map(move |id| world.rwa(&id).ok().map(entry_to_rwa)),
                    )
                } else {
                    Box::new(world.rwas_iter().map(entry_to_rwa))
                };
            Ok(iter.filter(move |rwa| {
                if let Some(predicate) = predicate_json.as_ref() {
                    predicate_matches_rwa(predicate, rwa)
                } else {
                    filter.applies(rwa)
                }
            }))
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            block::ValidBlock,
            kura::Kura,
            query::store::LiveQueryStore,
            state::{State, World},
        };
        use core::num::NonZeroU64;
        use iroha_crypto::{Algorithm, KeyPair};
        use iroha_model_base::metadata::Metadata;
        use iroha_primitives::json::Json;
        use iroha_test_samples::ALICE_ID;
        fn checked_keypair() -> KeyPair {
            KeyPair::try_random().expect("RWA query fixture key generation should succeed")
        }
        fn checked_account_id() -> AccountId {
            AccountId::new(checked_keypair().public_key().clone())
        }
        #[test]
        fn checked_keypair_preserves_default_algorithm() {
            assert_eq!(checked_keypair().algorithm(), Algorithm::default());
        }
        fn new_dummy_block() -> crate::block::CommittedBlock {
            let (leader_public_key, leader_private_key) = checked_keypair().into_parts();
            let peer_id = iroha_model_base::peer::PeerId::new(leader_public_key);
            let topology = crate::sumeragi::network_topology::Topology::new(vec![peer_id]);
            ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
                h.set_height(NonZeroU64::new(1).unwrap());
            })
            .commit(&topology, crate::block::reserve_block_for_tests())
            .unpack(|_| {})
            .unwrap()
        }
        fn seed_domain_name_lease(
            world: &mut crate::state::WorldTransaction<'_, '_>,
            owner: &AccountId,
            domain_id: &DomainId,
        ) {
            let selector = crate::sns::selector_for_domain(domain_id).expect("selector");
            let address =
                iroha_data_model::account::AccountAddress::from_account_id(owner).expect("address");
            let record = iroha_data_model::sns::NameRecordV1::new(
                selector.clone(),
                owner.clone(),
                vec![iroha_data_model::sns::NameControllerV1::account(&address)],
                0,
                0,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                Metadata::default(),
            );
            world.smart_contract_state_mut_for_testing().insert(
                crate::sns::record_storage_key(&selector),
                norito::codec::Encode::encode(&record),
            );
        }
        #[test]
        fn find_rwas_applies_predicate() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
                [0xC7; iroha_crypto::Hash::LENGTH],
            ));
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            seed_domain_name_lease(&mut stx.world, &ALICE_ID, &domain_id);
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            RegisterRwa {
                rwa: NewRwa::new(
                    domain_id,
                    "2".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/filter".to_owned(),
                    None,
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            let rwa_id = stx.world.rwas.iter().next().unwrap().0.clone();
            SetKeyValue::rwa(rwa_id.clone(), "grade".parse().unwrap(), Json::from("A"))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate = CompoundPredicate::<Rwa>::build(|p| p.equals("metadata.grade", "A"));
            let results: Vec<_> = FindRwas
                .execute(predicate, &view)
                .unwrap()
                .map(|rwa| rwa.id)
                .collect();
            assert_eq!(results, vec![rwa_id]);
        }
        #[test]
        fn find_rwas_filters_owner_with_owner_index() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
                [0xD4; iroha_crypto::Hash::LENGTH],
            ));
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            let recipient = checked_account_id();
            seed_domain_name_lease(&mut stx.world, &ALICE_ID, &domain_id);
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(recipient.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            RegisterRwa {
                rwa: NewRwa::new(
                    domain_id.clone(),
                    "2".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/owner-filter-a".to_owned(),
                    None,
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            let recipient_rwa_id = stx.world.rwas.iter().next().unwrap().0.clone();
            TransferRwa {
                source: ALICE_ID.clone(),
                rwa: recipient_rwa_id.clone(),
                quantity: "2".parse::<Quantity>().unwrap(),
                destination: recipient.clone(),
            }
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            RegisterRwa {
                rwa: NewRwa::new(
                    domain_id,
                    "3".parse::<Quantity>().unwrap(),
                    NumericSpec::integer(),
                    "https://example.test/rwa/owner-filter-b".to_owned(),
                    None,
                    Metadata::default(),
                    Vec::new(),
                    RwaControlPolicy::default(),
                ),
            }
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            assert!(
                stx.world
                    .rwas_by_owner
                    .get(&recipient)
                    .is_some_and(|ids| ids.contains(&recipient_rwa_id)),
                "recipient-owned lot should be present in the owner index before commit",
            );
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let predicate =
                CompoundPredicate::<Rwa>::build(|p| p.equals("owner", recipient.to_string()));
            let results: Vec<_> = FindRwas
                .execute(predicate, &view)
                .unwrap()
                .map(|rwa| rwa.id)
                .collect();
            assert_eq!(results, vec![recipient_rwa_id]);
        }
        #[test]
        fn find_rwas_intersects_status_and_frozen_wsv_indexes() {
            let kura = Kura::blank_kura_for_testing();
            let query_handle = LiveQueryStore::start_test();
            let state = State::new(World::default(), kura, query_handle);
            let block = new_dummy_block();
            let mut state_block = state.block(block.as_ref().header());
            let mut stx = state_block.transaction();
            stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
                [0xE5; iroha_crypto::Hash::LENGTH],
            ));
            let domain_id: DomainId = DomainId::try_new("vault", "universal").unwrap();
            seed_domain_name_lease(&mut stx.world, &ALICE_ID, &domain_id);
            Register::domain(Domain::new(domain_id.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            Register::account(Account::new(ALICE_ID.clone()))
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            let vaulted = "vaulted".parse::<Name>().unwrap();
            let pending = "pending".parse::<Name>().unwrap();
            let freezing_controls = RwaControlPolicy {
                controller_accounts: vec![ALICE_ID.clone()],
                freeze_enabled: true,
                ..RwaControlPolicy::default()
            };
            for (reference, status, controls) in [
                (
                    "https://example.test/rwa/status-frozen-target",
                    vaulted.clone(),
                    freezing_controls.clone(),
                ),
                (
                    "https://example.test/rwa/status-only",
                    vaulted.clone(),
                    RwaControlPolicy::default(),
                ),
                (
                    "https://example.test/rwa/frozen-only",
                    pending,
                    freezing_controls,
                ),
            ] {
                RegisterRwa {
                    rwa: NewRwa::new(
                        domain_id.clone(),
                        "2".parse::<Quantity>().unwrap(),
                        NumericSpec::integer(),
                        reference.to_owned(),
                        Some(status),
                        Metadata::default(),
                        Vec::new(),
                        controls,
                    ),
                }
                .execute(&ALICE_ID, &mut stx)
                .unwrap();
            }
            let target_id = stx
                .world
                .rwas
                .iter()
                .find(|(_, value)| {
                    value.primary_reference == "https://example.test/rwa/status-frozen-target"
                })
                .map(|(id, _)| id.clone())
                .expect("target RWA id");
            FreezeRwa {
                rwa: target_id.clone(),
            }
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            let frozen_only_id = stx
                .world
                .rwas
                .iter()
                .find(|(_, value)| {
                    value.primary_reference == "https://example.test/rwa/frozen-only"
                })
                .map(|(id, _)| id.clone())
                .expect("frozen-only RWA id");
            FreezeRwa {
                rwa: frozen_only_id,
            }
            .execute(&ALICE_ID, &mut stx)
            .unwrap();
            assert!(
                stx.world
                    .rwas_by_status
                    .get(&Some(vaulted.clone()))
                    .is_some_and(|ids| ids.contains(&target_id)),
                "target lot should be present in the status index before commit",
            );
            assert!(
                stx.world
                    .rwas_by_frozen
                    .get(&true)
                    .is_some_and(|ids| ids.contains(&target_id)),
                "target lot should be present in the frozen-state index before commit",
            );
            let predicate = CompoundPredicate::<Rwa>::build(|p| {
                p.equals("status", "vaulted".to_owned())
                    .equals("frozen", true)
            });
            let predicate_view = RwaPredicateView::from_predicate(&predicate);
            let candidate_ids = predicate_view
                .indexed_candidate_ids(&stx.world)
                .expect("indexed RWA candidates");
            assert_eq!(candidate_ids, BTreeSet::from([target_id.clone()]));
            stx.apply();
            state_block.commit_world_overlay_for_testing().unwrap();
            let view = state.view();
            let results: Vec<_> = FindRwas
                .execute(predicate, &view)
                .unwrap()
                .map(|rwa| rwa.id)
                .collect();
            assert_eq!(results, vec![target_id]);
        }
    }
}

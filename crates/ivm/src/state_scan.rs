//! Metered, seek-based live keyset pagination shared by every V1 state host.
//!
//! The host supplies an authoritative instance binding and an ordered stream of
//! current candidate positions. Overlay tombstones consume the same position
//! budget as live keys. A full page carries a continuation without probing for
//! another key; the following page can therefore be empty.
use std::ops::{Bound, ControlFlow};

use iroha_allocation::AllocationReservation;
use iroha_crypto::Hash;
use iroha_data_model::smart_contract::state_cursor::{MAX_STATE_CURSOR_BYTES_V1, StateCursorV1};
use iroha_model_base::{name::Name, state_path::StatePath};
#[cfg(test)]
use ivm_abi::codec::decode_canonical_norito;
use ivm_abi::codec::encode_canonical_norito;

use crate::{
    IVM, VMError, gas, host, metadata::EmbeddedStateType, pointer_abi::PointerType, syscalls,
};

/// Maximum logical positions examined by one scan, including deleted entries.
pub const MAX_STATE_SCAN_CANDIDATES_V1: usize = syscalls::STATE_SCAN_MAX_CANDIDATES_V1;
/// Domain separating a map's exact key/value schema from other ABI hashes.
pub use iroha_data_model::smart_contract::state_cursor::STATE_CURSOR_SCHEMA_HASH_DOMAIN_V1;

/// Validated scan inputs, bound to the currently loaded contract interface.
pub struct StateScanRequest {
    map: StatePath,
    after: Option<StatePath>,
    limit: usize,
    instance: String,
    schema_hash: [u8; 32],
    key_schema_hash: [u8; 32],
    input_gas: u64,
    // The original input-decode allowance follows the owned map, continuation,
    // and instance until they are destroyed. This owner is intentionally not Clone.
    _reservation: Option<AllocationReservation>,
}

fn payload_at(vm: &IVM, register: usize, maximum: usize) -> Result<&[u8], VMError> {
    let tlv = vm.validate_tlv(vm.register(register))?;
    if tlv.type_id != PointerType::NoritoBytes || tlv.payload.len() > maximum {
        return Err(VMError::NoritoInvalid);
    }
    Ok(tlv.payload)
}

/// Quote request bytes before inspecting a map, its schema, or any backing state.
pub fn prepare_minimum(vm: &IVM) -> Result<u64, VMError> {
    if !(1..=64).contains(&vm.register(12)) || (13..=15).any(|reg| vm.register(reg) != 0) {
        return Err(VMError::NoritoInvalid);
    }
    let path = host::quote_state_path_payload_len_at(vm, vm.register(10))?;
    let cursor = if vm.register(11) == 0 {
        0
    } else {
        let len = host::quote_tlv_payload_len_at(vm, vm.register(11), PointerType::NoritoBytes)?;
        if len > MAX_STATE_CURSOR_BYTES_V1 {
            return Err(VMError::NoritoInvalid);
        }
        len
    };
    Ok(gas::STATE_QUERY_GAS_BASE.saturating_add((path + cursor + 256) as u64))
}

fn unavailable() -> VMError {
    VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable)
}

fn codec_error(error: norito::Error) -> VMError {
    match error {
        norito::Error::AllocationFailed { .. } => unavailable(),
        _ => VMError::NoritoInvalid,
    }
}

fn decode_request_value<T>(
    reservation: &mut Option<AllocationReservation>,
    limits: norito::core::DecodeLimits,
    decode: impl FnOnce() -> Result<T, norito::Error>,
) -> Result<T, VMError> {
    let context = match reservation.as_mut() {
        Some(reservation) => norito::core::DecodeBudgetContext::from_reservation(
            limits,
            reservation,
        )
        .map_err(|error| match error {
            iroha_allocation::PrepaidSharedError::Reservation(_) => {
                VMError::ExecutionDeferred(crate::ExecutionDeferral::LocalInvariantViolation)
            }
            iroha_allocation::PrepaidSharedError::Allocator { .. } => unavailable(),
        })?,
        None => norito::core::DecodeBudgetContext::new(limits),
    };
    context.with(decode).map_err(codec_error)
}

impl StateScanRequest {
    /// Decode the published inputs and authenticate the cursor's position binding.
    ///
    /// `instance` is derived from host invocation context, never a guest input.
    pub fn decode(vm: &IVM, instance: &str) -> Result<Self, VMError> {
        let minimum = prepare_minimum(vm)?;
        host::preflight_reserved_syscall_gas(vm, minimum)?;
        if instance.is_empty() || instance.len() > 1024 {
            return Err(VMError::NoritoInvalid);
        }
        let map_payload = payload_at(vm, 10, syscalls::STATE_MAX_PATH_FRAME_BYTES)?;
        let cursor_payload = (vm.register(11) != 0)
            .then(|| payload_at(vm, 11, MAX_STATE_CURSOR_BYTES_V1))
            .transpose()?;
        let map_limits = norito::canonical_decode_limits(map_payload.len());
        // Use the cursor model's exact bounded decode policy. The reservation is
        // conservative for the retained subset: no clone, reacquisition, or pool
        // substitution is needed when the cursor's last key becomes `after`.
        let cursor_limits = norito::core::DecodeLimits::new(
            MAX_STATE_CURSOR_BYTES_V1,
            MAX_STATE_CURSOR_BYTES_V1,
            MAX_STATE_CURSOR_BYTES_V1,
            MAX_STATE_CURSOR_BYTES_V1 * 8,
            16,
        );
        let context_bytes = norito::core::DecodeBudgetContext::allocation_layout().size();
        let input_bytes = map_limits.max_total_allocated_bytes()
            + context_bytes
            + instance.len()
            + cursor_payload.map_or(0, |_| {
                cursor_limits.max_total_allocated_bytes() + context_bytes
            });
        let mut reservation = vm
            .allocation_budget()
            .map(|pool| pool.try_reserve_bytes(input_bytes))
            .transpose()
            .map_err(VMError::AllocationDeferred)?;
        let map: StatePath = decode_request_value(&mut reservation, map_limits, || {
            norito::decode_canonical_with_limits(map_payload, map_limits)
        })?;
        let name: Name = map.as_ref().parse().map_err(|_| VMError::NoritoInvalid)?;
        let interface = vm.contract_interface().ok_or(VMError::InvalidMetadata)?;
        let mut declarations = interface
            .states
            .iter()
            .filter(|state| state.name == name.as_ref());
        let declaration = declarations.next().ok_or(VMError::NoritoInvalid)?;
        if declarations.next().is_some() {
            return Err(VMError::NoritoInvalid);
        }
        let EmbeddedStateType::StateMap { key, .. } = &declaration.ty else {
            return Err(VMError::NoritoInvalid);
        };
        // The schema is signed and admission-bounded. Charge its full encoding
        // before allocation/hashing, in addition to the public input envelopes.
        // Admission bounds every value schema to 64 KiB and 256 nodes. The
        // recursive embedded representation adds only fixed child envelopes;
        // reserve those before the encoder builds its bounded temporary tree.
        const SCHEMA_ENCODING_BOUND: usize = ivm_abi::state_value::MAX_STATE_VALUE_SCHEMA_BYTES
            + (ivm_abi::state_value::MAX_STATE_VALUE_NODES + 2) * 64
            + 1024;
        host::preflight_reserved_syscall_gas(
            vm,
            minimum.saturating_add(SCHEMA_ENCODING_BOUND as u64),
        )?;
        // Projection, embedded-schema encoding and cursor validation scratch
        // are bounded separately and die before the retained request is returned.
        // Four complete schema envelopes cover simultaneous child/parent encoder
        // backing and its bounded traversal; key nodes have a distinct exact bound.
        let scratch_bytes = 4 * SCHEMA_ENCODING_BOUND
            + ivm_abi::entrypoint::MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES
                * core::mem::size_of::<ivm_abi::entrypoint::EntrypointValueTypeNodeV1>();
        let _scratch_reservation = vm
            .allocation_budget()
            .map(|pool| pool.try_reserve_bytes(scratch_bytes))
            .transpose()
            .map_err(VMError::AllocationDeferred)?;
        let key_schema = ivm_abi::state_value::state_map_key_schema_v1(key).map_err(codec_error)?;
        let key_schema_hash =
            iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(&key_schema)
                .ok_or(VMError::NoritoInvalid)?;
        let schema = norito::encode_canonical(&declaration.ty).map_err(codec_error)?;
        if schema.len() > SCHEMA_ENCODING_BOUND {
            return Err(VMError::NoritoInvalid);
        }
        // The 256-byte empty-response reservation is an allocation preflight;
        // charge the actual serialized response only when publishing the page.
        let input_gas = minimum
            .saturating_sub(256)
            .saturating_add(schema.len() as u64)
            .saturating_add(instance.len() as u64);
        let schema_hash =
            Hash::new_from_chunks(&[STATE_CURSOR_SCHEMA_HASH_DOMAIN_V1, &schema]).into();
        let after = if let Some(payload) = cursor_payload {
            let cursor = decode_request_value(&mut reservation, cursor_limits, || {
                StateCursorV1::decode_frame(payload)
            })?;
            if !cursor.validate()
                || cursor.instance != instance
                || cursor.map != map
                || cursor.schema_hash != schema_hash
                || cursor.key_schema_hash != key_schema_hash
            {
                return Err(VMError::NoritoInvalid);
            }
            host::validate_declared_state_path(vm, &cursor.last_key)?;
            Some(cursor.last_key)
        } else {
            None
        };
        let mut owned_instance = String::new();
        owned_instance
            .try_reserve_exact(instance.len())
            .map_err(|_| unavailable())?;
        owned_instance.push_str(instance);
        Ok(Self {
            map,
            after,
            limit: vm.register(12) as usize,
            instance: owned_instance,
            schema_hash,
            key_schema_hash,
            input_gas,
            _reservation: reservation,
        })
    }

    /// Borrow the bare source map name while its original custody owner remains live.
    pub fn map(&self) -> &StatePath {
        &self.map
    }

    /// Borrow the exclusive continuation position without detaching its allocation custody.
    pub fn after(&self) -> Option<&StatePath> {
        self.after.as_ref()
    }

    /// Ordered lower bound for a backing store using unprefixed source paths.
    pub fn lower_bound<'a>(&'a self, prefix: &'a str) -> Bound<&'a str> {
        self.after.as_ref().map_or(Bound::Included(prefix), |path| {
            Bound::Excluded(path.as_ref())
        })
    }

    fn cursor(&self, last_key: StatePath) -> StateCursorV1 {
        StateCursorV1 {
            instance: self.instance.clone(),
            map: self.map.clone(),
            schema_hash: self.schema_hash,
            key_schema_hash: self.key_schema_hash,
            last_key,
        }
    }
}

/// One bounded page under construction. Callers must stop on `Break`.
pub struct StateScanPage {
    request: StateScanRequest,
    selected: Vec<StatePath>,
    examined: usize,
    last: Option<StatePath>,
    bounded: bool,
    work_gas: u64,
    selected_encoded_bytes: usize,
    response_bound: usize,
}

impl StateScanPage {
    /// Start a page without reading any backing state.
    pub fn new(request: StateScanRequest) -> Self {
        let work_gas = request.input_gas;
        Self {
            request,
            selected: Vec::new(),
            examined: 0,
            last: None,
            bounded: false,
            work_gas,
            selected_encoded_bytes: 0,
            response_bound: 256,
        }
    }

    /// Account for one ordered candidate, including tombstones, before cloning it.
    ///
    /// `physical_bytes` includes the authoritative namespace used by the backing
    /// store, so its examined bytes are metered even though returned paths are relative.
    pub fn examine(
        &mut self,
        vm: &IVM,
        relative: &str,
        physical_bytes: usize,
        present: bool,
    ) -> Result<ControlFlow<()>, VMError> {
        if self.bounded {
            return Err(VMError::NoritoInvalid);
        }
        let prefix = self.request.map.as_ref();
        if !relative
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err(VMError::NoritoInvalid);
        }
        if self
            .last
            .as_ref()
            .or(self.request.after.as_ref())
            .is_some_and(|last| relative <= last.as_ref())
        {
            return Err(VMError::NoritoInvalid);
        }
        let work = self
            .work_gas
            .saturating_add(gas::STATE_SCAN_ITEM_GAS)
            .saturating_add(physical_bytes as u64);
        host::preflight_reserved_syscall_gas(
            vm,
            work.saturating_add(self.response_bound as u64)
                .saturating_add(MAX_STATE_CURSOR_BYTES_V1 as u64),
        )?;
        let key: StatePath = relative.parse().map_err(|_| VMError::NoritoInvalid)?;
        host::validate_declared_state_path(vm, &key)?;
        if present {
            let (elements, response) = host::state_scan_response_tail_after_item(
                self.selected.len(),
                self.selected_encoded_bytes,
                relative,
            )?;
            host::preflight_reserved_syscall_gas(
                vm,
                work.saturating_add(response as u64)
                    .saturating_add(MAX_STATE_CURSOR_BYTES_V1 as u64),
            )?;
            self.selected_encoded_bytes = elements;
            self.response_bound = response;
            self.selected.push(key.clone());
        }
        self.last = Some(key);
        self.work_gas = work;
        self.examined += 1;
        self.bounded = self.examined == MAX_STATE_SCAN_CANDIDATES_V1
            || self.selected.len() == self.request.limit;
        Ok(if self.bounded {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        })
    }

    /// Publish the completed key page and continuation after preflighting both outputs.
    pub fn publish(self, vm: &mut IVM) -> Result<u64, VMError> {
        let payload = encode_canonical_norito(&self.selected)?;
        let cursor_payload = if self.bounded {
            let last = self.last.ok_or(VMError::NoritoInvalid)?;
            Some(
                self.request
                    .cursor(last)
                    .encode_frame()
                    .map_err(|_| VMError::NoritoInvalid)?,
            )
        } else {
            None
        };
        let bytes = payload.len() + cursor_payload.as_ref().map_or(0, Vec::len);
        let gas = self.work_gas.saturating_add(bytes as u64);
        host::preflight_reserved_syscall_gas(vm, gas)?;
        let keys_pointer = publish_bytes(vm, &payload)?;
        let cursor_pointer = cursor_payload
            .as_ref()
            .map_or(Ok(0), |payload| publish_bytes(vm, payload))?;
        vm.set_register(10, keys_pointer);
        vm.set_register(11, cursor_pointer);
        vm.set_register(12, self.selected.len() as u64);
        vm.set_register(13, self.examined as u64);
        Ok(gas)
    }
}

fn publish_bytes(vm: &mut IVM, payload: &[u8]) -> Result<u64, VMError> {
    let mut tlv = Vec::with_capacity(host::TLV_ENVELOPE_OVERHEAD + payload.len());
    tlv.extend_from_slice(&(PointerType::NoritoBytes as u16).to_be_bytes());
    tlv.push(1);
    tlv.extend_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| VMError::NoritoInvalid)?
            .to_be_bytes(),
    );
    tlv.extend_from_slice(payload);
    tlv.extend_from_slice(Hash::new(payload).as_ref());
    vm.alloc_host_tlv(&tlv)
}

/// Merge sorted backing keys and transaction entries without collecting either range.
/// Overlay entries override backing presence; each distinct position is yielded once.
pub fn merge_candidates<'a>(
    backing: impl Iterator<Item = &'a StatePath>,
    overlay: impl Iterator<Item = (&'a StatePath, bool)>,
) -> impl Iterator<Item = (&'a StatePath, bool)> {
    let mut backing = backing.peekable();
    let mut overlay = overlay.peekable();
    std::iter::from_fn(move || match (backing.peek(), overlay.peek()) {
        (Some(base), Some((entry, _))) if *base < *entry => backing.next().map(|key| (key, true)),
        (Some(base), Some((entry, _))) if *base == *entry => {
            backing.next();
            overlay.next()
        }
        (_, Some(_)) => overlay.next(),
        (Some(_), None) => backing.next().map(|key| (key, true)),
        (None, None) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoreHost, host::IVMHost};
    use std::collections::BTreeMap;

    fn vm(gas: u64) -> IVM {
        let code = kotodama_lang::compiler::Compiler::new().compile_source(
            "seiyaku Scan { state StateMap<string, int> orders; state StateMap<string, int> other; view fn main() authorize(anyone) { () } }",
        ).expect("compile scan contract");
        let mut vm = IVM::new(gas);
        vm.load_program(&code).expect("load scan contract");
        vm
    }

    pub(super) fn key(index: usize) -> StatePath {
        let text = format!("{index:04}");
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&(PointerType::Blob as u16).to_be_bytes());
        envelope.push(1);
        envelope.extend_from_slice(&(text.len() as u32).to_be_bytes());
        envelope.extend_from_slice(text.as_bytes());
        envelope.extend_from_slice(Hash::new(text.as_bytes()).as_ref());
        use ivm_abi::state_value::{
            StateValueAtomV1, StateValueKindV1, StateValueNodeV1, StateValueRecordV1,
            StateValueSchemaV1, state_value_schema_hash_v1,
        };
        let schema = StateValueSchemaV1 {
            nodes: vec![StateValueNodeV1::Leaf(StateValueKindV1::String)],
        };
        let record = StateValueRecordV1 {
            schema_hash: state_value_schema_hash_v1(&encode_canonical_norito(&schema).unwrap()),
            atoms: vec![StateValueAtomV1::Pointer(envelope)],
        };
        host::canonical_state_map_path(
            &"orders".parse().unwrap(),
            &encode_canonical_norito(&record).unwrap(),
        )
        .unwrap()
    }

    pub(super) fn arguments(vm: &mut IVM, map: &str, cursor: Option<&[u8]>, limit: u64) {
        let map: StatePath = map.parse().unwrap();
        let path = publish_bytes(vm, &encode_canonical_norito(&map).unwrap()).unwrap();
        let cursor = cursor.map_or(0, |cursor| publish_bytes(vm, cursor).unwrap());
        vm.set_register(10, path);
        vm.set_register(11, cursor);
        vm.set_register(12, limit);
        for register in 13..=15 {
            vm.set_register(register, 0);
        }
    }

    fn result(vm: &IVM) -> (Vec<StatePath>, Option<Vec<u8>>, usize) {
        let keys =
            decode_canonical_norito(vm.validate_tlv(vm.register(10)).unwrap().payload).unwrap();
        let cursor = (vm.register(11) != 0)
            .then(|| vm.validate_tlv(vm.register(11)).unwrap().payload.to_vec());
        (keys, cursor, vm.register(13) as usize)
    }

    #[test]
    fn live_pages_cover_large_maps_without_counting_or_extra_lookahead() {
        let mut vm = vm(u64::MAX);
        let mut host = CoreHost::new();
        let mut expected = Vec::new();
        for index in 0..192 {
            let key = key(index);
            host.insert_state_value(key.as_ref(), b"scan does not fetch values");
            expected.push(key);
        }
        expected.sort();
        let mut cursor = None;
        let mut observed = Vec::new();
        let mut examined_pages = Vec::new();
        loop {
            arguments(&mut vm, "orders", cursor.as_deref(), 64);
            host.syscall(syscalls::SYSCALL_STATE_SCAN, &mut vm).unwrap();
            let (items, next, examined) = result(&vm);
            assert!(examined <= 64);
            examined_pages.push(examined);
            observed.extend(items);
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(observed, expected);
        assert_eq!(
            examined_pages,
            [64, 64, 64, 0],
            "a full final page must not probe for exhaustion"
        );
    }

    #[test]
    fn cursor_survives_deletion_and_reads_current_inter_page_insertions() {
        let mut vm = vm(u64::MAX);
        let mut host = CoreHost::new();
        let keys = (10..60).map(key).collect::<std::collections::BTreeSet<_>>();
        for key in &keys {
            host.insert_state_value(key.as_ref(), b"value");
        }
        arguments(&mut vm, "orders", None, 10);
        host.syscall(syscalls::SYSCALL_STATE_SCAN, &mut vm).unwrap();
        let (first, cursor, _) = result(&vm);
        let cursor = cursor.unwrap();
        let last = first.last().unwrap();
        let pointer = publish_bytes(&mut vm, &encode_canonical_norito(last).unwrap()).unwrap();
        vm.set_register(10, pointer);
        host.syscall(syscalls::SYSCALL_STATE_DEL, &mut vm).unwrap();
        // Canonical record bytes, including their checksums, define the ordering.
        let before = (100..1000).map(key).find(|key| key < last).unwrap();
        let after = (100..1000).map(key).find(|key| key > last).unwrap();
        host.insert_state_value(before.as_ref(), b"insert before cursor");
        host.insert_state_value(after.as_ref(), b"insert after cursor");
        arguments(&mut vm, "orders", Some(&cursor), 64);
        host.syscall(syscalls::SYSCALL_STATE_SCAN, &mut vm).unwrap();
        let (second, _, _) = result(&vm);
        let mut expected = keys
            .into_iter()
            .filter(|key| key > last)
            .collect::<Vec<_>>();
        expected.push(after);
        expected.sort();
        assert_eq!(second, expected);
    }

    #[test]
    fn cursor_rejects_wrong_instance_map_schema_and_key_schema() {
        let mut vm = vm(u64::MAX);
        let mut host = CoreHost::new();
        host.set_state_instance("instance-a".into()).unwrap();
        host.insert_state_value(key(1).as_ref(), b"value");
        arguments(&mut vm, "orders", None, 1);
        host.syscall(syscalls::SYSCALL_STATE_SCAN, &mut vm).unwrap();
        let (_, cursor, _) = result(&vm);
        let cursor = cursor.unwrap();
        arguments(&mut vm, "other", Some(&cursor), 1);
        assert!(host.syscall(syscalls::SYSCALL_STATE_SCAN, &mut vm).is_err());
        host.set_state_instance("instance-b".into()).unwrap();
        arguments(&mut vm, "orders", Some(&cursor), 1);
        assert!(host.syscall(syscalls::SYSCALL_STATE_SCAN, &mut vm).is_err());
        host.set_state_instance("instance-a".into()).unwrap();
        for change_kind in [false, true] {
            let mut altered = StateCursorV1::decode_frame(&cursor).unwrap();
            if change_kind {
                altered.key_schema_hash = [99; 32];
            } else {
                altered.schema_hash[0] ^= 1;
            }
            arguments(&mut vm, "orders", Some(&altered.encode_frame().unwrap()), 1);
            assert!(host.syscall(syscalls::SYSCALL_STATE_SCAN, &mut vm).is_err());
        }
        for limit in [0, 65] {
            arguments(&mut vm, "orders", None, limit);
            assert!(
                host.prepare_syscall(syscalls::SYSCALL_STATE_SCAN, &vm)
                    .is_err()
            );
        }
    }

    #[test]
    fn overlay_tombstones_consume_the_bounded_candidate_budget() {
        let mut vm = vm(u64::MAX);
        arguments(&mut vm, "orders", None, 64);
        let request = StateScanRequest::decode(&vm, "local").unwrap();
        let mut page = StateScanPage::new(request);
        let backing = (0..100)
            .map(|index| (key(index), ()))
            .collect::<BTreeMap<_, _>>();
        let overlay = backing
            .keys()
            .take(64)
            .cloned()
            .map(|key| (key, false))
            .collect::<BTreeMap<_, _>>();
        let mut consumed = 0;
        for (key, present) in merge_candidates(
            backing.keys(),
            overlay.iter().map(|(key, present)| (key, *present)),
        ) {
            consumed += 1;
            if page
                .examine(&vm, key.as_ref(), key.as_ref().len(), present)
                .unwrap()
                .is_break()
            {
                break;
            }
        }
        page.publish(&mut vm).unwrap();
        let (items, cursor, examined) = result(&vm);
        assert!(items.is_empty());
        assert!(cursor.is_some());
        assert_eq!((consumed, examined), (64, 64));
    }

    #[test]
    fn dispatched_scan_exhausts_gas_before_publishing_output() {
        let mut vm = vm(8_000);
        let mut host = CoreHost::new();
        host.insert_state_value(key(1).as_ref(), b"value");
        arguments(&mut vm, "orders", None, 1);
        let path = vm.register(10);
        let error = vm
            .execute_syscall(&mut host, syscalls::SYSCALL_STATE_SCAN)
            .unwrap_err();
        assert!(
            matches!(error.as_unmetered(), VMError::OutOfGas),
            "{error:?}"
        );
        assert_eq!(vm.register(10), path);
    }
}

#[cfg(test)]
#[path = "state_scan/request_custody_tests.rs"]
mod request_custody_tests;

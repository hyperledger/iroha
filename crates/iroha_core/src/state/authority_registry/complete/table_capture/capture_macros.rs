// Scoped adapters retain the exact State pool; resource policy grants no authority.

// Every invocation names an actual typed World storage field. The fixed catalog
// below checks identity and order against the complete nested registry before
// any reader can run. Each reader still issues only a scoped, non-finalized pair.
macro_rules! capture_world_table_once {
    ($vis:vis $name:ident, $field:ident, $identity:literal) => {
        #[doc = concat!("Capture the complete native rows of `", $identity, "` at a stable generation.")]
        $vis fn $name(
            state: &State,
            limits: LeafLimits,
        ) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
            let generation = state.state_view_generation();
            if generation & 1 != 0 {
                return Ok(None);
            }
            let budget = state.pipeline_ivm_prepared_cache.read().execution_budget().clone();
            let rows = state.world.$field.view();
            let snapshot =
                CanonicalTableLeafSet::paired_table_from_rows($identity, limits, &budget, rows.iter())?;
            drop(rows);
            if !is_stable_state_view_generation(generation, state.state_view_generation()) {
                return Ok(None);
            }
            Ok(Some(snapshot))
        }

        // Rust's type and value namespaces keep the existing callable reader
        // beside its one generated descriptor. Identity and both concrete field
        // callbacks are declared together; the static catalog cannot pair them
        // with a second independently maintained frozen registry.
        $vis mod $name {
            use super::*;

            /// One declared native field with its two concrete observation forms.
            pub(in crate::state::authority_registry::complete::table_capture) const MATERIALIZER: TableMaterializer = TableMaterializer::Native {
                id: $identity,
                capture: super::$name,
                frozen,
            };

            fn frozen(
                block: &StateBlock<'_>,
                limits: LeafLimits,
            ) -> Result<Option<CanonicalTablePairedSnapshot>, LeafError> {
                let Some(fields) = block.fields.as_ref() else {
                    return Ok(None);
                };
                if fields.world.publication != crate::state::block_field::AggregatePublication::Frozen {
                    return Ok(None);
                }
                let Some(rows) = fields.world.$field.frozen_images() else {
                    return Ok(None);
                };
                if !rows.belongs_to(&fields.state_ref.world.$field) {
                    return Ok(None);
                }
                // Preserve the exact native storage mode and original private
                // current image. Do not acquire State views, refresh the source
                // or accept a pool.
                // This singleton does not certify other fields' identities or
                // acquisition modes; complete publication must bind them jointly.
                CanonicalTableLeafSet::paired_table_from_rows(
                    $identity,
                    limits,
                    &fields.state_ref.ivm_execution_budget,
                    rows.current_entries(),
                ).map(Some)
            }
        }
    };
}

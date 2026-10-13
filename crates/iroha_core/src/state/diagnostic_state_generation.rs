impl State {
    /// Derive one read-only diagnostic projection from a single committed State
    /// generation.
    ///
    /// Individual State views already retry their own lock acquisition, but a
    /// diagnostic can combine several views with bounded Kura/Queue reads in
    /// between. Rechecking the outer generation prevents a lane lifecycle captured
    /// before scale-out or recreation from filtering evidence using a later
    /// WSV/validator view. Fallible observations from a changed generation are
    /// discarded and retried just like successful ones. The fixed attempt bound
    /// prevents sustained block publication from turning an operator request into
    /// an unbounded sequence of full evidence scans.
    #[cfg(test)]
    fn derive_diagnostics_at_stable_state_generation<T, E>(
        &self,
        mut derive: impl FnMut() -> core::result::Result<T, E>,
        generation_drift_error: impl Fn() -> E,
    ) -> core::result::Result<T, E> {
        for _ in 0..DIAGNOSTIC_STABLE_STATE_GENERATION_ATTEMPTS {
            let generation_before = self.state_view_generation();
            if !generation_before.is_multiple_of(2) {
                std::thread::yield_now();
                continue;
            }
            let result = derive();
            let generation_after = self.state_view_generation();
            if is_stable_state_view_generation(generation_before, generation_after) {
                return result;
            }
            std::thread::yield_now();
        }
        Err(generation_drift_error())
    }
}

// This qualification fixture must fail compilation: read-only views are not mutating calls.
fun cannotRouteViewAsCall(value: ksampleBindings.ViewRequest<ksampleBindings.T1_kPayload>): ksampleBindings.KotoageRequest<ksampleBindings.T1_kPayload> = value

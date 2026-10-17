# E0 independent return projection review

Read-only review of `return_machine.py` against source `codec::encode_as`,
extended field order and the retained profile dimensions is clear under its
generation premises. The mathematical envelope is error1, last-counter32,
proof-length64, then proof bytes. It is not the native enum wire encoding.
On success the fixed field projection follows source order; exhaustion copies
the original last counter2^20−1 and no proof. It adds no decoder, challenge
comparison or auxiliary-success decision.

Five independent cases passed, including exhaustive one-byte source values
under both exhaustion tags and endpoint last counters with arbitrary target
bits, complete input/work preservation and double application. Controls expose
dirty work after removed uncompute, proof leakage after removed success
control, and a changed source during the second identity read.

The source factory pins three selected files; this is not a dependency closure
or runtime proof. Correct row, lengths, salt and success counter come from the
generating stages, matching the checks of source encoding. Whole-history
cleanup and the oracle/adversary joint projection remain separate obligations.
All qualification flags remain false; no tracked edits or native execution.

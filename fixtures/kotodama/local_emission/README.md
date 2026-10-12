# Local compiler emission controls

The sole production compiler retains an original synchronous syscall result in r10
through its sole verified local consumer. Global definition/use counts, canonical
register/spill homes, same-block order and every scheduled split reload bound the
lifetime. Only zero-emission DataRef markers may intervene. Unknown consumers,
shared or multiply defined values, spill homes and return-register reloads retain
ordinary materialization. The ABI argument mover consumes all original register
sources before literal or spill loads overwrite an input register. The original
exact two-input schema/data state decoder uses that same existing parallel mover;
its owned allocation and every following table-word read remain. Only unique
single-word tables may avoid an intermediate copy; shared tables remain ordinary.

Consecutive entry LoadVar reads may share their exact incoming authenticated table
base in reserved r27. Every original word load and spill write remains. Any split
reload before an entry read disables reuse; later reads retain the saved base.
When all parameter reads belong to that uninterrupted prefix, its unused private
argument-base store is omitted. Callable ownership, argument/result schemas and
frame sizes remain exact. Source instructions, authenticated snapshots, canonical
serialization, allocations, checks, permissions and runtime metering are unchanged.

Only unit tests retain the preceding scalar emission behind a scoped, unwinding
thread-local guard. There is no production option or second implementation owner.
The complete source-bound inventory in cases.rs requires eleven genuinely captured
native pairs. The eight current compact sources are reused directly, including the
cross-function abort. Additional sources exercise shared values across repeated
private calls, dynamic branch/state chains, canonical quantity maps and checked
underflow. The capture loader rejects missing, additional, duplicate, oversized,
noncanonical or changed rows and verifies every complete source/artifact hash.

The compiler test capture_actual_local_emission_native_pairs prints actual
LOCAL_EMISSION_NATIVE rows. Save only their six payload fields to native_v1.tsv,
then run local_pairs_reproduce_current_full_compiler_artifacts_and_exact_public_abi
and the compiler::local_emission controls. These compare complete artifacts and
metadata, preserve every original syscall count and report code, CNTR and literal
sizes for the actual production DLMM source.

Run the eight local_emission consumers in ivm's kotodama_dead_operands target.
They load the genuine artifacts through the actual IVM verifier and execute them
on DefaultHost/CoreHost and the actual permission-bearing WsvHost. They compare
all typed results, full nominal error identities and raw/committed state bytes;
transactional failures use CoreHost's real checkpoint, begin_tx, finish_tx and
restore. Map consumers also inspect actual paid state/path/serialization steps,
drop the VM before checking retained state, and prove quantity underflow rolls
back all preceding writes. Both map sources initialize their scalar Total to typed
quantity zero in the genuine hajimari entrypoint. Their native consumers execute
that constructor on each original empty host, then checkpoint the exact Total=0
state before main; failed main execution restores that constructor state. The
three final values and complete paid map consumers remain checked. Zero-gas
execution retains the original refusal.

The checked-in eleven rows are the capture of the current compiler and sources;
the compiler parity control and the eight local_emission consumers pass on them.

TODO: the unchanged default4M payout, 64gas/byte policy, real XOR fee execution
and complete disposable-network qualification require their own same-candidate
runtime evidence. Compiler byte savings alone do not establish them.

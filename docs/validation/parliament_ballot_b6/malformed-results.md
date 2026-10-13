# Standalone malformed-encoding observations

Status: **experimental; no profile, production mapping or hardware qualified**.
Both release feature modes completed 164 selected row/case/mutation classes,
31 repeated observations per class: **5,084 per mode, 10,168 total**. All
rejections had the expected public boundary. All 164 paired input digests,
lengths, rejection outcomes and untimed diagnostic classes match across modes.
The [raw portable](malformed-portable.jsonl) and [raw accelerated](malformed-accel.jsonl)
records retain every sample and each class's min, median, p95 and maximum.

The [runner method](../../../crates/iroha_parliament_ballot_proof/examples/QUALIFICATION.md#malformed-encoding-observations)
uses maximum registration fields and votes with 3, 500 and 1,000 seats. It
constructs and accepts one fixed test proof per row/case, then constructs each
mutant outside timing. Four malformed proof classes require their specific
backend codec error before measurement; other mutations must fail record or
statement decoding. Timed calls use ordinary fresh-profile, cold-input
verification. Each mutant is repeated in a warm process after preflight; these
are not fresh random trials or cold-process/cache observations.

| Mode | Row | Case | Largest observed time (ms) | Class at that maximum | Maximum requested live Rust heap (bytes) |
| --- | --- | --- | ---: | --- | ---: |
| portable | candidate | registration | 0.818834 | `proof_counter_above_limit` | 518,243 |
| portable | candidate | vote3 | 0.743334 | `proof_opening_above_capacity` | 648,667 |
| portable | candidate | vote500 | 1.917166 | `proof_counter_above_limit` | 984,454 |
| portable | candidate | vote1000 | 3.320459 | `proof_grinding_bit_set` | 1,496,454 |
| portable | comparator | registration | 0.781458 | `proof_nonzero_opening_padding` | 414,967 |
| portable | comparator | vote3 | 0.720500 | `proof_nonzero_opening_padding` | 496,815 |
| portable | comparator | vote500 | 1.864625 | `proof_nonzero_opening_padding` | 834,578 |
| portable | comparator | vote1000 | 3.262208 | `proof_grinding_bit_set` | 1,346,578 |
| accel | candidate | registration | 8.360167 | `proof_nonzero_opening_padding` | 518,237 |
| accel | candidate | vote3 | 3.681000 | `proof_opening_above_capacity` | 648,661 |
| accel | candidate | vote500 | 4.247500 | `proof_nonzero_opening_padding` | 984,448 |
| accel | candidate | vote1000 | 10.844625 | `proof_opening_above_capacity` | 1,496,448 |
| accel | comparator | registration | 5.072000 | `wrong_statement_tag` | 414,961 |
| accel | comparator | vote3 | 2.409292 | `record_proof_length_zero` | 496,809 |
| accel | comparator | vote500 | 3.530000 | `proof_nonzero_opening_padding` | 834,572 |
| accel | comparator | vote1000 | 6.043209 | `proof_opening_above_capacity` | 1,346,572 |

These are maxima among the recorded observations, not worst-case bounds. The
canonical record, one mutant, diagnostics and bounded metric bookkeeping remain
live and are included in requested Rust heap. Stack, allocator overhead,
native heaps and RSS are excluded. This shared M2 Ultra host was concurrently
running upstream C verification and other development; portable compilation
overlapped the accelerated campaign. No isolated or thermal baseline is claimed.

## Identity and validation

The [225-file source manifest](malformed-source.sha256) includes the original
measurement source scope plus the new malformed module and tests; its digest is
`7cc9ad79e452fe3cfd58cc0fdc570a7d5b76614f7352d9c13ba9b17be670a409`. Source hashes were checked before and after both runs.
The [receipt](malformed-receipt.json) retains separate binary hashes, compiler,
normal revision metadata, hardware, commands and limitations. The original
seven-phase/device runs retain their earlier source identity. The
[forward runner patch](post-measurement-malformed-runner.patch) and
[hash record](post-measurement-malformed-runner.json) preserve reconstruction of
that earlier snapshot without changing the live checkout.

The five new helper tests and eight existing runner tests pass in both modes
(13/13 each); strict release Clippy passes both modes. Scoped formatting and
the no-legacy-codec guard pass. The all-case mutation test requires exact codec
variants for counter overflow, grinding bits, decommitment padding and opening
capacity. The honest-setup test exercises one full run and its reporting.

The separate validation below checks class/sample counts, expected outcomes,
source/binary hashes, all six distribution fields against raw samples, heap
metric identities and feature parity. It produced the
[summary](malformed-summary.json) and [validation output](malformed-validation.txt).
The proof implementation and production gate were not modified.

## Commands

```sh
scripts/cargo_fast.sh --target-slot parliament-ballot --incremental -- build --release -p iroha_parliament_ballot_proof --example qualify --features accel
# Copy resulting executable to /tmp/parliament-b6-malformed-accel and hash it.
/tmp/parliament-b6-malformed-accel malformed --samples 31 --source-id 7cc9ad79e452fe3cfd58cc0fdc570a7d5b76614f7352d9c13ba9b17be670a409 --run-id mac-m2-ultra-malformed-accel > docs/validation/parliament_ballot_b6/malformed-accel.jsonl
# Repeat build without --features accel, copying and running the portable executable.
scripts/cargo_fast.sh --target-slot parliament-ballot --incremental -- test --release -p iroha_parliament_ballot_proof --example qualify --features accel -- --test-threads=1
scripts/cargo_fast.sh --target-slot parliament-ballot --incremental -- clippy --release -p iroha_parliament_ballot_proof --example qualify --features accel -- -D warnings
# Repeat test/lint without --features accel.
cargo +1.93.1 fmt -p iroha_parliament_ballot_proof -p iroha_zkp_vole -- --check
scripts/check_no_legacy_codec.sh
```

Analysis command, run from the repository root after both campaigns (the
referenced temporary binaries must still exist for the binary checks):

```python
from pathlib import Path
import collections,datetime,hashlib,json,math,subprocess
root=Path.cwd();e=root/'docs/validation/parliament_ballot_b6'
source_id=hashlib.sha256((e/'malformed-source.sha256').read_bytes()).hexdigest()
for line in (e/'malformed-source.sha256').read_text().splitlines():
    expected,path=line.split('  ',1)
    assert hashlib.sha256((root/path).read_bytes()).hexdigest()==expected,path
summary={'source_id':source_id,'profile_qualified':False,'modes':{}}
parity={}
for mode in ['portable','accel']:
    path=e/f'malformed-{mode}.jsonl'
    rows=[json.loads(line) for line in path.read_text().splitlines()]
    assert collections.Counter(r['kind'] for r in rows)=={'run_header':1,'run_complete':1,'malformed_sample':5084,'malformed_summary':164}
    assert rows[0]['source_id']==source_id and rows[0]['accel_feature']==(mode=='accel')
    assert rows[0]['samples_per_case']==31 and rows[0]['profile_qualified'] is False
    assert rows[-1]=={'kind':'run_complete','profile_qualified':False}
    groups=collections.defaultdict(list);stats={}
    for row in rows:
        if row['kind']=='malformed_sample': groups[(row['row'],row['case'],row['mutation'])].append(row)
        if row['kind']=='malformed_summary': stats[(row['row'],row['case'],row['mutation'])]=row
    assert len(groups)==len(stats)==164
    parity[mode]={}
    case_reports=[]
    for key,samples in groups.items():
        assert [s['sample_index'] for s in samples]==list(range(31))
        assert len({(s['record_shake256_32'],s['outcome'],s['record_bytes']) for s in samples})==1
        expected='verification_rejected' if key[2] in {'proof_counter_above_limit','proof_grinding_bit_set','proof_nonzero_opening_padding','proof_opening_above_capacity'} else 'decode_rejected'
        assert all(s['outcome']==expected for s in samples)
        for metric in ['elapsed_ns','total_peak_live_bytes','incremental_peak_bytes','live_at_entry_bytes','allocation_calls','allocated_bytes']:
            values=sorted(s['metric'][metric] for s in samples)
            assert stats[key]['metrics'][metric]=={'count':31,'min':values[0],'median':values[15],'p95':values[29],'max':values[30]},(key,metric)
        for s in samples:
            m=s['metric'];assert m['total_peak_live_bytes']>=max(m['live_at_entry_bytes'],m['live_at_exit_bytes'])
            assert m['incremental_peak_bytes']==m['total_peak_live_bytes']-m['live_at_entry_bytes']
        parity[mode][key]=(samples[0]['record_shake256_32'],samples[0]['outcome'],samples[0]['record_bytes'],stats[key]['diagnostic'])
    for row in ['candidate','comparator']:
        for case in ['registration','vote3','vote500','vote1000']:
            keys=[key for key in groups if key[:2]==(row,case)]
            assert len(keys)==(16 if case=='registration' else 22)
            worst=max(keys,key=lambda k:stats[k]['metrics']['elapsed_ns']['max'])
            case_reports.append({'row':row,'case':case,'classes':len(keys),'samples':len(keys)*31,'largest_observed_elapsed_ns':stats[worst]['metrics']['elapsed_ns']['max'],'largest_elapsed_mutation':worst[2],'max_total_peak_live_bytes':max(stats[k]['metrics']['total_peak_live_bytes']['max'] for k in keys),'max_incremental_peak_bytes':max(stats[k]['metrics']['incremental_peak_bytes']['max'] for k in keys)})
    summary['modes'][mode]={'samples':5084,'classes':164,'raw_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'by_case':case_reports}
assert parity['portable']==parity['accel']
summary['feature_parity']={'classes':164,'sample_pairs':5084,'input_digest_length_outcome_diagnostic_equal':True}
(e/'malformed-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
p=e/'malformed-receipt.json';r=json.loads(p.read_text())
for b in r['binaries'].values(): assert hashlib.sha256(Path(b['path']).read_bytes()).hexdigest()==b['sha256']
r.update({'completed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_hashes_match_before_and_after':True,'samples_each_mode':5084,'classes_each_mode':164,'feature_parity':summary['feature_parity'],'machine_reference':'mac-machine.json (same host); os/hardware rechecked below','os':subprocess.check_output(['sw_vers'],text=True),'hardware':subprocess.check_output(['sysctl','-n','machdep.cpu.brand_string','hw.physicalcpu','hw.logicalcpu','hw.memsize'],text=True),'build_command':'scripts/cargo_fast.sh --target-slot parliament-ballot --incremental -- build --release -p iroha_parliament_ballot_proof --example qualify [--features accel]','run_command':'/tmp/parliament-b6-malformed-{portable|accel} malformed --samples 31 --source-id '+source_id+' --run-id mac-m2-ultra-malformed-{portable|accel}','tests':'13/13 example tests per mode; strict release Clippy per mode; scoped two-crate format and no-legacy-codec checks pass','limitations':['Shared M2 Ultra host with concurrent upstream C verification and other development. Portable compilation overlapped accelerated observations. No isolation, cache flush, cooldown or baseline qualification.','One fixed proof/mutant per class; 31 repetitions after preflight in a warm process. Construction, proving and diagnostics untimed.','Canonical record, one mutant and harness bookkeeping included in requested Rust heap; no stack/native/RSS/allocator-overhead ceiling.','Malformed campaign covers 164 selected classes, not exhaustive malformed inputs or adversarial worst case.','Binary hashes identify copied local builds; not external attestation or release qualification. Old device campaigns retain their original 223-file snapshot.']})
p.write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(summary,indent=2))
```

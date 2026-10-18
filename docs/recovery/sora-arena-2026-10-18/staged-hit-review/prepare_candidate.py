#!/usr/bin/env python3
"""Create a review-only native patch. Never mutate the native checkout or build."""
from pathlib import Path
import argparse, datetime, difflib, hashlib, json, os, shutil, subprocess

OUT=Path(__file__).resolve().parent
NATIVE=Path('/Users/takemiyamakoto/soramitsudev/iroha-arena')
GAME=Path('/Users/takemiyamakoto/soramitsudev/sora-arena')
BASE='8209033deae7409d800fcc576a63609a0c2c5f9d'
PREFIX='crates/iroha_core/src/execution_proofs/'
FILES=[PREFIX+n for n in ['arena_aim_air.rs','arena_geometry_air.rs','arena_staged_hit_air.rs','arena_staged_hit_stark_research.rs','integer_air.rs','checked_integer_air.rs','mod.rs']]+['crates/iroha_core/tests/fixtures/arena_staged_hit_reference.json']
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--evidence',type=Path,required=True,help='Source-matching completed proof harness directory')
parser.add_argument('--historical-proof',action='store_true',help='Retain earlier-source proof explicitly as historical, not candidate qualification')
parser.add_argument('--expected-fixture-sha256',required=True)
ARGS=parser.parse_args()
EVIDENCE=ARGS.evidence.resolve()

def digest(data): return hashlib.sha256(data).hexdigest()
def git(*args): return subprocess.check_output(['git','--no-optional-locks','-C',str(NATIVE),*args])
def base_bytes(name):
    r=subprocess.run(['git','--no-optional-locks','-C',str(NATIVE),'show',BASE+':'+name],capture_output=True)
    if r.returncode:
        assert b'does not exist' in r.stderr or b'exists on disk, but not in' in r.stderr,r.stderr
        return None
    return r.stdout

def write(name,data):
    p=OUT/name
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f: f.write(data if isinstance(data,bytes) else data.encode())

def json_write(name,data): write(name,json.dumps(data,indent=2,sort_keys=True)+'\n')
def patch_one(name,before,after):
    lines=[f'diff --git a/{name} b/{name}\n']
    if before is None: lines.append('new file mode 100644\n')
    lines.extend(difflib.unified_diff((before or b'').decode().splitlines(keepends=True),after.decode().splitlines(keepends=True),fromfile='a/'+name if before is not None else '/dev/null',tofile='b/'+name))
    return ''.join(lines)

def native_guard():
    paths={name:digest((NATIVE/name).read_bytes()) for name in FILES}
    for name in ['index','config']:
        raw=git('rev-parse','--git-path',name).decode().strip()
        path=Path(raw) if Path(raw).is_absolute() else NATIVE/raw
        paths['git:'+name]=digest(path.read_bytes()) if path.exists() else None
    return {'head':git('rev-parse','HEAD').decode().strip(),'refs_sha256':digest(git('show-ref')),'selected_source_and_git_metadata':paths}

before_guard=native_guard()
assert before_guard['head']==BASE
run=json.loads((EVIDENCE/'run-status.json').read_text())
provenance=json.loads((EVIDENCE/'source-provenance.json').read_text())
assert run['status']=='proof_verified' and run['qualified'] is False and run['registered'] is False
for name,expected in run['artifacts_sha256'].items():
    assert digest((EVIDENCE/name).read_bytes())==expected,(name,'evidence changed')
historical_source_mismatches=[]
for name,expected in provenance['sources'].items():
    actual=digest((NATIVE/name).read_bytes())
    if actual!=expected:
        historical_source_mismatches.append({'path':name,'historical_proof_sha256':expected,'candidate_sha256':actual})
assert ARGS.historical_proof or not historical_source_mismatches, 'native source drifted from proof'
current_fixture=digest((NATIVE/FILES[-1]).read_bytes())
assert current_fixture==ARGS.expected_fixture_sha256
assert digest((GAME/'crates/arena-core/tests/data/staged_hit_reference.json').read_bytes())==current_fixture

files=[]
patches=[]
base_dir=OUT/'base-snapshot'
base_dir.mkdir()
for name in FILES:
    old=base_bytes(name)
    working=(NATIVE/name).read_bytes()
    new=working
    if name==PREFIX+'mod.rs':
        marker=b'#[cfg(test)]\nmod checked_integer_air;'
        assert old.count(marker)==1
        replacement=b'mod arena_aim_air;\nmod arena_geometry_air;\nmod arena_staged_hit_air;\npub mod arena_staged_hit_stark_research;\nmod checked_integer_air;'
        new=old.replace(marker,replacement,1)
    if old is not None: write('base-snapshot/'+name,old)
    write('candidate-files/'+name,new)
    patches.append(patch_one(name,old,new))
    files.append({'path':name,'base_sha256':digest(old) if old is not None else None,'base_git_blob':git('rev-parse',BASE+':'+name).decode().strip() if old is not None else None,'candidate_sha256':digest(new),'observed_working_tree_sha256':digest(working),'bytes':len(new),'mode':'100644','selection':'surgical replacement against base' if name==PREFIX+'mod.rs' else 'complete working file'})
patch=''.join(patches)
write('native-staged-hit.patch',patch)

DOC=PREFIX+'README-arena-staged-hit.md'
assert base_bytes(DOC) is None and not (NATIVE/DOC).exists()
measurements=dict(line.split('=',1) for line in (EVIDENCE/'result/measurements.txt').read_text().splitlines() if '=' in line)
assert measurements['qualified']=='false' and measurements['research_only']=='true'
proof_bytes=f"{int(measurements['proof_bytes']):,}"
negative_count=int(measurements['negative_verifications'])
doc='''# Arena staged ray selection research

`arena_staged_hit_stark_research` exposes inspection, proving and verification of
one ordered ray-stop computation over a public snapshot. It derives the ray
from yaw/pitch and constrains slab arithmetic, eligibility, strict nearest-hit
selection, and state carried across the candidate scan. Bounds are 1–12 players,
0–64 walls and 0–48 entities. Static walls precede entities and original player
slots; ties preserve the earlier candidate. The shared reference fixture is
`../../tests/fixtures/arena_staged_hit_reference.json`.

The native adapter retains 8,192 rows, degree four, 136 queries, 8× LDE, FRI
terminal size 1,024 and degree 143, four composition chunks, and a 4 MiB proof
cap. It is unregistered and unqualified. This component does not authenticate a
World boundary, establish legal attacks or damage, prove kills, or authorize
custody, NFT equipment, XOR rewards or settlement. Complete execution and
four-validator qualification remain required.

A source-sealed research harness on 2026-10-18 used the full dirty native tree
based on `8209033deae7409d800fcc576a63609a0c2c5f9d`, not an isolated eight-file
candidate build. For the 12-player/64-wall/48-entity `bounded_random_9` fixture,
it verified a PROOF_BYTES-byte proof and NEGATIVE_COUNT negative verifications. The
final candidate changes three Copy derives and refreshes source hashes in the
fixture; that final source has not been re-proved. These historical measurements
qualify neither the final candidate nor a complete match. Its
source seal, pinned dependency artifacts and raw results live with the SORA
Arena qualification record, not in this native patch.

The game runner also imports native `scripts/check_arena_geometry_stark.py`.
That currently untracked helper is outside this component patch; these eight
files alone do not package that runner. Build and test an isolated candidate
before integration. Changing shared `integer_air.rs` changes the source-bound
Race profile identity. Race qualification remains false; no old identity,
compatibility alias or decoder is retained.
'''
doc=doc.replace('PROOF_BYTES',proof_bytes).replace('NEGATIVE_COUNT',str(negative_count))
write('component-readme.patch',patch_one(DOC,None,doc.encode()))
write('candidate-files/'+DOC,doc)

check_env=os.environ.copy()
check_env['GIT_CEILING_DIRECTORIES']=str(OUT)
checks=[]
for patch_name in ['native-staged-hit.patch','component-readme.patch']:
    cmd=['git','apply','--check','--whitespace=error-all',str(OUT/patch_name)]
    result=subprocess.run(cmd,cwd=base_dir,env=check_env,capture_output=True,text=True)
    checks.append({'command':cmd,'cwd':str(base_dir),'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr,'scope':'read-only applicability against copied sparse base files; no compilation'})
    assert result.returncode==0,result.stderr
json_write('apply-check.json',checks)

unchanged=[]
for name,expected in provenance['sources'].items():
    if name not in FILES:
        old=base_bytes(name)
        assert old is not None and digest(old)==expected,(name,'extra dirty dependency')
        unchanged.append({'path':name,'base_and_working_tree_sha256':expected,'git_blob':git('rev-parse',BASE+':'+name).decode().strip()})
helper='scripts/check_arena_geometry_stark.py'
assert base_bytes(helper) is None
helper_hash=digest((NATIVE/helper).read_bytes())
assert digest((GAME/'crates/arena-core/tests/data/staged_hit_reference.json').read_bytes())==files[-1]['candidate_sha256']
historical_fixture_hash=digest((EVIDENCE/'reference-fixture.json').read_bytes())
assert ARGS.historical_proof or historical_fixture_hash==files[-1]['candidate_sha256'], 'final proof fixture differs from game/native candidate fixture'
assert json.loads((EVIDENCE/'reference-fixture.json').read_text())['cases']==json.loads((NATIVE/FILES[-1]).read_text())['cases'], 'fixture cases changed from measured proof reference'
selected_tree=''.join(x['path']+'\0'+x['candidate_sha256']+'\n' for x in sorted(files,key=lambda x:x['path'])).encode()
proof_seal=json.loads((EVIDENCE/'seal-before.json').read_text())
manifest={'schema':'sora-arena.native-staged-hit.review-candidate.v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'native_root':str(NATIVE),'base_commit':BASE,'base_git_tree':git('rev-parse',BASE+'^{tree}').decode().strip(),'candidate_scope':'eight-file component patch; optional new README is a separate patch','candidate_selected_tree_sha256':digest(selected_tree),'candidate_tree_hash_encoding':'UTF-8 sorted path + NUL + lowercase SHA-256 + LF for each of eight candidate files; not a Git tree ID','files':files,'unchanged_native_source_dependencies':unchanged,'patch_sha256':digest(patch.encode()),'component_readme':{'path':DOC,'sha256':digest(doc.encode()),'patch_sha256':digest((OUT/'component-readme.patch').read_bytes())},'validation':{'patch_applicability':True,'isolated_candidate_built':False,'isolated_candidate_tested':False,'native_build_launched':False,'native_commit_created':False,'registered':False,'qualified':False},'previous_proof_evidence':{'path':str(EVIDENCE),'run_status_sha256':digest((EVIDENCE/'run-status.json').read_bytes()),'source_provenance_sha256':digest((EVIDENCE/'source-provenance.json').read_bytes()),'native_tree_seal':proof_seal['source'],'all_artifact_hashes_verified':True,'all_referenced_sources_match_current':not historical_source_mismatches,'historical_source_mismatches':historical_source_mismatches,'historical_fixture_sha256':historical_fixture_hash,'fixture_matches_candidate':historical_fixture_hash==current_fixture,'fixture_cases_identical':True,'final_source_proof_pending':bool(historical_source_mismatches) or historical_fixture_hash!=current_fixture,'scope':'source-sealed extracted native harness compiled from full dirty checkout with pinned prebuilt dependencies; not isolated patch qualification'},'unpackaged_runner_dependency':{'path':helper,'sha256':helper_hash,'tracked_in_base':False},'gpg_executable':shutil.which('gpg'),'explicit_exclusions':['Cargo.toml','Cargo.lock','full dirty execution_proofs/mod.rs','registry/proof/custody/SDK/staking changes','native runner helper','existing unrelated README/status/roadmap edits']}
after_guard=native_guard()
assert before_guard==after_guard,'native source/index/config/refs changed during external artifact preparation'
json_write('native-before.json',before_guard)
json_write('native-after.json',after_guard)
json_write('manifest.json',manifest)
def optional_git(*args):
    result=subprocess.run(['git','--no-optional-locks','-C',str(NATIVE),*args],capture_output=True,text=True)
    return result.stdout.strip() if result.returncode==0 else None
status=git('status','--porcelain=v1','--untracked-files=all').decode().splitlines()
staged=git('diff','--cached','--name-only').decode().splitlines()
policy='Never bypass commit signing (do not use `git commit --no-gpg-sign`). If GPG signing is not available in the automation environment, leave the change uncommitted and ask the user to create a signed commit locally.'
assert policy in (NATIVE/'AGENTS.md').read_text()
json_write('native-review-state.json',{'head':before_guard['head'],'branch':optional_git('symbolic-ref','--short','HEAD'),'staged_paths':staged,'staged_path_count':len(staged),'dirty_tracked_path_count':sum(not line.startswith('??') for line in status),'untracked_path_count':sum(line.startswith('??') for line in status),'commit_gpgsign':optional_git('config','--get','commit.gpgsign'),'gpg_format':optional_git('config','--get','gpg.format'),'gpg_program':optional_git('config','--get','gpg.program'),'gpg_executable':shutil.which('gpg'),'signing_policy_source':str(NATIVE/'AGENTS.md'),'signing_policy_quote':policy,'native_commit_created':False,'native_mutations':False,'safe_next_actions':['Review the isolated candidate, build and test it before integration.','Create a signed commit with the configured local signing identity when its signing program is available, or have the local maintainer commit this preserved patch.','Do not bypass commit signing or include unrelated dirty native work.']})
readme='''# Review-only native staged-hit candidate

This bundle contains an eight-file native component patch against commit
`8209033deae7409d800fcc576a63609a0c2c5f9d`. It was prepared outside the native
checkout. No native source, index, configuration, refs or commit were changed,
and no build was launched. Captured native guards before and after are equal.

- `native-staged-hit.patch`: four new AIR/adapter files, the shared fixture,
  complete existing changes to `integer_air.rs` and `checked_integer_air.rs`,
  and only the required five-line module registration from base `mod.rs`.
- `component-readme.patch`: optional new source-adjacent component note; it
  modifies none of the dirty native documentation.
- `manifest.json`: exact base Git tree and file blobs, base/candidate/observed
  SHA-256 hashes, unchanged native dependency hashes, exclusions, and evidence
  scope. The selected-file SHA-256 is not a Git tree ID.
- `base-snapshot/` and `candidate-files/`: review copies only.
- `apply-check.json`: successful read-only `git apply --check` checks against
  copied base files, with whitespace errors rejected. No patch was applied to
  the native checkout. `prepare_candidate.py` documents the construction.

The isolated candidate has NOT been built or tested. A full dirty-tree Core
integration run after the Copy fixes passed 2 tests with 1 ignored; it does not
qualify this isolated patch or prove the final source. The proof already run
used a source-sealed harness extracted from the full dirty native checkout,
with prebuilt pinned dependencies. Its complete artifact hashes were checked while creating this bundle. The
final candidate changes three Copy derives and refreshes only the source-hash
metadata in the fixture; all case bytes are identical. The two differing source
hashes and earlier fixture hash are recorded in the manifest. Final-source
proof regeneration is pending and was not started, following the user's stop
instruction. That earlier proof establishes
only one conditional public-snapshot ray-selection computation. It does not
prove authenticated World state, legal attack initiation, damage, a kill,
settlement, or a full 12-player match. Registration and qualification stay false.

The code dependency closure is eight files plus unchanged native dependencies
already in the base. Compilation remains unvalidated. Reproducing the separate
game runner additionally requires the current untracked native helper
`scripts/check_arena_geometry_stark.py`; this bundle records its exact hash but
does not silently include it. The helper, dependencies and full-tree evidence
must not be mistaken for artifacts supplied by the isolated patch.

Shared `integer_air.rs` is hashed by the Race source inventory, so this patch
changes the derived Race profile identity even though `proof.rs` is excluded.
The base Race qualification flag is already false. No backward-compatibility
aliases, historical-ID fallbacks or decoder paths were added.

GPG is absent from PATH in this environment. No unsigned native commit was
created and signing was not bypassed. A signed commit and isolated candidate
build/test qualification remain integration work. See `native-review-state.json`
for the observed branch, index, signing settings and exact repository policy.
The safe options are a signed commit using the configured local signing
identity once available, or preservation of this patch for a local maintainer
to review and commit with signing. Disabling signing is not an option.
'''
write('README.md',readme)
print(json.dumps({'output':str(OUT),'files':len(files),'patch_bytes':len(patch.encode()),'patch_sha256':digest(patch.encode()),'apply_checks':[x['exit_code'] for x in checks],'source_guards_equal':True,'isolated_candidate_built':False},indent=2))

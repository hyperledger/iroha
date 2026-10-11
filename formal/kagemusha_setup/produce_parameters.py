"""Explicit fresh-output CLI for a synthetic chosen-parameter family."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import random
import sys
import time
from .bounded import Limits, Owner, TracedMemory, new_output, artifact_inventory
from .custody import HERE, checked_sources, require, sha


def main():
    require(sys.flags.optimize == 0, 'unoptimized producer only')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--k',type=int,action='append',dest='domains')
    parser.add_argument('--curves',choices=('0','1','0,1'),default='0,1')
    parser.add_argument('--allow-large',action='store_true')
    parser.add_argument('--contexts',type=int,default=132)
    parser.add_argument('--queries',type=int,default=1024)
    parser.add_argument('--entries',type=int,default=412)
    parser.add_argument('--request-cap',type=int,default=8)
    parser.add_argument('--memory-mib',type=int,default=32)
    parser.add_argument('--output-mib',type=int,default=1)
    parser.add_argument('--seed',type=int,default=2026100944)
    args = parser.parse_args()
    domains = [6] if args.domains is None else args.domains
    require(1 <= len(domains) <= 17 and len(set(domains)) == len(domains),
            'one bounded request per selected domain')
    require(all(type(k) is int and 0 <= k <= 16 for k in domains), 'selected domains')
    tags = [int(tag) for tag in args.curves.split(',')]
    limits = Limits(max_k=max(domains),contexts=args.contexts,queries=args.queries,
                    entries=args.entries,requests=args.request_cap,
                    memory_bytes=args.memory_mib << 20,output_bytes=args.output_mib << 20,
                    allow_large=args.allow_large).validate()
    require(len(domains)*len(tags) <= limits.requests, 'scheduled requests fit budget')
    expected_contexts = len(tags)*((1 << max(domains))+2)
    require(expected_contexts <= limits.contexts, 'scheduled contexts fit budget')
    require(3*sum((1 << k)+2 for k in domains)*len(tags) <= limits.queries,
            'scheduled raw calls fit budget')
    require(3*expected_contexts <= limits.entries, 'scheduled raw entries fit budget')
    require(sum(64*(1 << k)+68 for k in domains)*len(tags) <= limits.output_bytes,
            'scheduled wire bytes fit budget')
    require(type(args.seed) is int and 0 <= args.seed < 1 << 256, 'bounded diagnostic seed')
    before = checked_sources()
    output = new_output(args.output)
    def save(name,value):
        with (output/name).open('x') as stream:
            json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')
    save('started.json',{'argv':sys.argv,'limits':asdict(limits),'seed':args.seed,
         'domains':domains,'curves':tags,'expected_contexts':expected_contexts,
         'manifest_sha256':sha((HERE/'source_manifest.json').read_bytes()),
         'scope':'Synthetic ideal raw-RO setup only; not production authority or C12'})
    start, owner, memory = time.monotonic(), None, None
    record = {'success':False,'current_setup_qualified':False,'C12_closed':False,
              'parameter_outputs':[],'family_resamples':0,'seed':args.seed}
    try:
        # Only after all scheduling/resource/source guards and fresh output.
        from . import raw_setup, parameters
        memory = TracedMemory(limits.memory_bytes)
        owner = Owner(raw_setup,parameters,random.Random(args.seed),limits,memory=memory)
        for tag in tags:
            for k in domains:
                data = owner.derive(tag,k)
                prefix = str(tag)+'-k'+str(k)
                wire_path = output/(prefix+'-parameters.bin')
                with wire_path.open('xb') as stream:
                    stream.write(data.raw)
                # Stream large log vectors; no duplicate all-family JSON tree.
                with (output/(prefix+'-logs-private.jsonl')).open('x') as stream:
                    for role in ('g','lagrange'):
                        for index,value in enumerate(data.logs[role]):
                            stream.write(json.dumps({'role':role,'index':index,'scalar':value})+'\n')
                    for role in ('w','u'):
                        stream.write(json.dumps({'role':role,'scalar':data.logs[role]})+'\n')
                model = owner.sampler.models[tag]
                trivial_log = sum(data.logs['g']) % model.curve.scalar
                trivial = model.curve.multiply(data.base,trivial_log)
                save(prefix+'-identity.json',{'curve':tag,'k':k,'parameter_bytes':len(data.raw),
                     'parameter_sha256':sha(data.raw),'base':model.curve.encode(data.base).hex(),
                     'log_file':prefix+'-logs-private.jsonl','not_public_protocol_data':True,
                     'all_ones_generator':{'point':model.curve.encode(trivial).hex(),
                                           'private_log':trivial_log,'finite':trivial[2] != 0},
                     'all_ones_generator_is_derived_not_release_authority':True})
                record['parameter_outputs'].append({'curve':tag,'k':k,'bytes':len(data.raw),
                                                    'sha256':sha(data.raw)})
                del data
        require(len(owner.oracle.logs) == expected_contexts, 'exact scheduled setup contexts')
        after = checked_sources()
        require(after == before, 'unchanged source manifest')
        record.update(success=True,source_pins_unchanged=True)
        return 0
    except BaseException as error:
        record['failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        try:
            finalize(output,limits,owner,memory,record,before)
        finally:
            if memory is not None:
                memory.close()
            record['elapsed_seconds'] = time.monotonic()-start
            save('result.json',record)


def finalize(output,limits,owner,memory,record,before):
    """Admit success only after retention, all hashes and final allocation check."""
    try:
        if owner is not None:
            record['owner'] = owner.persist(output)
        # Exact finite wire/log/private-table upper allowance, not an RSS bound.
        disk_cap = (2*limits.output_bytes+1024*limits.entries+2048*limits.contexts+
                    512*limits.requests*((1 << limits.max_k)+1)+(4 << 20))
        record['artifacts'] = artifact_inventory(output,3*limits.requests+5,disk_cap)
        if record['success']:
            inventory = {row['name']:row for row in record['artifacts']}
            expected = {'started.json','raw-table-private.jsonl','context-logs-private.jsonl',
                        'sampler-attempts-private.jsonl','owner-state.json'}
            declared = set()
            for selected in record['parameter_outputs']:
                prefix = str(selected['curve'])+'-k'+str(selected['k'])
                name = prefix+'-parameters.bin'
                require(name not in declared,'duplicate selected parameter output')
                declared.add(name)
                expected.update((name,prefix+'-logs-private.jsonl',prefix+'-identity.json'))
                require(name in inventory and inventory[name]['bytes'] == selected['bytes'] and
                        inventory[name]['sha256'] == selected['sha256'],
                        'generated and retained parameter wire differ')
            require(set(inventory) == expected,'exact successful artifact namespace')
            record['generated_parameter_wires_match_retained'] = True
        require(checked_sources() == before,'source pins changed during final retention')
        if memory is not None:
            memory.checkpoint()
    except BaseException as error:
        record['success'] = False
        record['retention_failure'] = type(error).__name__+': '+str(error)
        raise
    finally:
        if memory is not None:
            record['traced_allocations'] = memory.observe()


if __name__ == '__main__':
    raise SystemExit(main())

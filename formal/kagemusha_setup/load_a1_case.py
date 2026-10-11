"""Closed historical Load A1 chosen outer setup diagnostic.

Import is inert: no reference/setup module, original, or parameter is loaded.
Only build() can enter the large path, after exact custody and explicit opt-in.
This is trusted diagnostic Python, not a production or hostile-code boundary.
"""
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager
import hashlib
import json
import os
import stat
import sys

from .custody import HERE, ROOT, checked_sources
D = (39386,'e7e535287ff5b2f41ff3c4a92dac549981b1dea243ba191930cc24932a51c087')
V = (2154,'04c6acf9d714bf3259dfb1b71606f7f655419548ab2bd5e930ecbd2418b2762c')
PK = (140511414,'04824c5fdb5d8f59ef66de7a822d170ece02134b50abe9b65b63ebe3b8fa3a34')
CHUNK = 1 << 20
MAX_MEMORY = 2 << 30
SETUP_RESERVATION = 532678860
CASE_ALLOWANCE = MAX_MEMORY - SETUP_RESERVATION
TERMINAL_ALLOWANCE = 256 << 10


def require(ok, why):
    if not ok: raise ValueError(why)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def identity(s): return s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns


def safe(path):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts)<=64,'absolute bounded path')
    for p in [*path.parents,path]:require(not p.is_symlink(),'no symbolic links')
    return path


def source_snapshot():
    """Authenticate the exact maintained package and dependencies before imports."""
    return checked_sources()


@dataclass(frozen=True)
class Limits:
    """Logical allowance and checkpointed allocation cap; neither reserves RAM."""
    memory_bytes: int = MAX_MEMORY
    output_bytes: int = 1 << 30
    files: int = 64
    depth: int = 4

    def validate(self):
        require(type(self.memory_bytes) is int and self.memory_bytes==MAX_MEMORY,
                'closed allocation ceiling')
        require(type(self.output_bytes) is int and 2*PK[0]+TERMINAL_ALLOWANCE<=self.output_bytes<=1<<30,
                'finite output byte budget')
        require(type(self.files) is int and 4<=self.files<=64 and
                type(self.depth) is int and 1<=self.depth<=4,'finite output shape')
        require(SETUP_RESERVATION+CASE_ALLOWANCE==self.memory_bytes,'one logical allowance equation')
        return self


def output_preflight(directory):
    path=safe(Path(directory).absolute())
    require(not path.exists() and path.parent.is_dir(),'fresh output with existing parent')
    return path


class Outputs:
    """One tree owner: charge every chunk before writing, then revalidate it."""
    def __init__(self,directory,limits):
        self.root=directory;self.limits=limits;self.used=0;self.records={};self.active=set()
        directory.mkdir(mode=0o700)
        require(stat.S_IMODE(directory.stat().st_mode)==0o700,'owner-only output')
        self.root_id=(directory.stat().st_dev,directory.stat().st_ino)

    def check_path(self,path):
        path=safe(Path(path));rel=path.relative_to(self.root)
        require(0<len(rel.parts)<=self.limits.depth,'output depth')
        require((self.root.stat().st_dev,self.root.stat().st_ino)==self.root_id,'output root changed')
        return str(rel)

    @contextmanager
    def stream(self,path,*,terminal=False):
        name=self.check_path(path)
        require(name not in self.records and name not in self.active,'fresh output name')
        require(len(self.records)+len(self.active)<self.limits.files-(0 if terminal else 3),
                'output file budget')
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        self.active.add(name);digest=hashlib.sha256();count=0
        with Path(path).open('xb') as out:
            def write(raw):
                nonlocal count
                require(type(raw) is bytes and len(raw)<=CHUNK,'bounded output chunk')
                limit=self.limits.output_bytes-(0 if terminal else TERMINAL_ALLOWANCE)
                require(len(raw)<=limit-self.used,'output byte budget before write')
                self.used+=len(raw);count+=len(raw);digest.update(raw)
                require(out.write(raw)==len(raw),'short output write')
            try:yield write
            finally:
                self.records[name]={'name':name,'bytes':count,'sha256':digest.hexdigest()}
                self.active.remove(name)

    def write(self,path,raw):
        require(type(raw) is bytes,'immutable output bytes')
        with self.stream(path) as emit:
            for i in range(0,len(raw),CHUNK):emit(raw[i:i+CHUNK])

    def save(self,path,value,*,terminal=False):
        with self.stream(path,terminal=terminal) as emit:
            for text in json.JSONEncoder(indent=2,sort_keys=True).iterencode(value):
                raw=text.encode()
                for i in range(0,len(raw),CHUNK):emit(raw[i:i+CHUNK])
            emit(b'\n')

    def verify(self):
        require(not self.active,'no partial live writer')
        actual=[]
        expected_dirs={str(p) for name in self.records for p in Path(name).parents if str(p)!='.'}
        for directory,subdirs,files in os.walk(self.root,followlinks=False):
            require(len(subdirs)+len(files)<=self.limits.files+16,'bounded output enumeration')
            for name in subdirs:
                child=Path(directory)/name;rel=self.check_path(child)
                require(not child.is_symlink() and rel in expected_dirs,'unexpected output directory')
            for name in files:
                path=Path(directory)/name;rel=self.check_path(path)
                require(rel in self.records,'unexpected output file')
                before=path.lstat();require(stat.S_ISREG(before.st_mode),'regular output')
                row=self.records[rel];require(before.st_size==row['bytes'],'retained output extent')
                digest=hashlib.sha256();count=0
                with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as stream:
                    opened=os.fstat(stream.fileno());require(identity(opened)==identity(before),'output changed before read')
                    while count<row['bytes']:
                        block=stream.read(min(CHUNK,row['bytes']-count));require(bool(block),'short output')
                        count+=len(block);digest.update(block)
                    require(not stream.read(1),'extended output')
                    require(identity(os.fstat(stream.fileno()))==identity(before),'output changed during read')
                require(identity(path.lstat())==identity(before) and digest.hexdigest()==row['sha256'],
                        'retained output hash/identity')
                actual.append(rel)
                require(len(actual)<=self.limits.files,'output file budget')
        require(set(actual)==set(self.records),'exact retained output namespace')
        return [self.records[name] for name in sorted(self.records)]


# The nofollow/identity algorithm below is retained from the reviewed A1 reader.

@contextmanager
def guarded_file(path, extent, observation):
    """Hold nofollow parent descriptors; compare descriptor and namespace identities."""
    path = safe(path)
    require(len(path.parts) <= 64, 'path component bound')
    opened_dirs, stream = [], None
    try:
        current = Path(path.anchor)
        fd = os.open(str(current), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened_dirs.append((current, fd, os.fstat(fd)))
        for component in path.parts[1:-1]:
            current = current / component
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened_dirs.append((current, fd, os.fstat(fd)))
        before = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        require(stat.S_ISREG(before.st_mode) and before.st_size == extent, 'original extent/type')
        raw_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        stream = os.fdopen(raw_fd, 'rb')
        opened = os.fstat(stream.fileno())
        require(identity(before) == identity(opened), 'original changed before read')
        observation['stat_identity_before'] = list(identity(before))
        yield stream
        finished = os.fstat(stream.fileno())
        selected = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        namespace = path.lstat()
        require(len({identity(s) for s in (before, opened, finished, selected, namespace)}) == 1,
                'original changed during read')
        for parent, parent_fd, prior in opened_dirs:
            now, named = os.fstat(parent_fd), parent.lstat()
            require(stat.S_ISDIR(named.st_mode) and (prior.st_dev, prior.st_ino)
                    == (now.st_dev, now.st_ino) == (named.st_dev, named.st_ino), 'original parent changed')
        observation['identities_unchanged'] = True
    finally:
        if stream is not None:
            stream.close()
        for _, fd, _ in reversed(opened_dirs):
            os.close(fd)


def read_original(path,pin,checkpoint=lambda:None,*,observation=None):
    """One full read/hash, retaining partial observations even on refusal."""
    extent,expected=pin
    observation={} if observation is None else observation
    observation.update(path=str(path),expected_bytes=extent,expected_sha256=expected,
                       bytes_read=0,bytes_hashed=0,extension_sentinel_bytes=None,passed=False)
    digest=hashlib.sha256();raw=bytearray()
    try:
        require(type(extent) is int and 0<extent<=PK[0] and type(expected) is str and len(expected)==64,
                'closed bounded original extent/digest')
        named=safe(path).lstat()
        observation.update(observed_namespace_bytes=named.st_size,namespace_identity=list(identity(named)))
        with guarded_file(path,extent,observation) as stream:
            while len(raw)<extent:
                block=stream.read(min(CHUNK,extent-len(raw)))
                observation['bytes_read']+=len(block)
                require(bool(block),'short original')
                raw.extend(block);digest.update(block);observation['bytes_hashed']+=len(block)
                checkpoint()
            sentinel=stream.read(1);observation['extension_sentinel_bytes']=len(sentinel)
            require(not sentinel,'extended original')
            require(digest.hexdigest()==expected,'exact original digest')
            result=bytes(raw);checkpoint()
        observation['passed']=True
        return result
    except BaseException as error:
        observation['error']=type(error).__name__+': '+str(error)[:1024]
        raise
    finally:observation['observed_sha256']=digest.hexdigest()


class Bits:
    """One sequential explicit source, no default/reset seed or alternate sampler."""
    def __init__(self,source):self.source=source;self.calls=0
    def getrandbits(self,width):
        require(type(width) is int and 1<=width<=512,'bounded setup bit width')
        self.calls+=1;value=self.source(width)
        require(type(value) is int and 0<=value<1<<width,'canonical setup bits')
        return value


@dataclass(frozen=True)
class Outcome:
    """Constructor result only; a successful case is not native source authority."""
    case: object | None
    error: str | None


def modules():
    """Deferred imports only after source/shape/custody entry admission."""
    from . import bounded, raw_setup, parameters, public_setup, rebind
    return bounded,raw_setup,parameters,public_setup,rebind


def check_profile(d):
    require(d.version==2 and sha(d.raw)==D[1] and d['curve']==1 and d['k']==16 and
            d['transcript']==2 and d['instance_mode']==1 and d['proof_suffix']==1 and
            d['instance_lengths']==[69] and d['degree']==8 and d['blinding_factors']==6 and
            d['num_fixed_columns']==51 and d['num_advice_columns']==23 and
            len(d['permutation'])==16 and d.permutation_sets==3 and len(d['lookups'])==4 and
            d['selectors'][0]==0,'closed historical A1 profile')


class Constructor:
    """One build, one actual setup owner, immutable replay, no detached intake.

    Private Python fields are diagnostic custody, not capabilities against
    monkeypatching. The same live setup/tracer is kept after successful build.
    close() ends that residual-query interface; no serialized resume is offered.
    originals selects only an existing directory of the three exact hash basenames;
    its location supplies no setup, catalog, or verifier authority.
    """
    def __init__(self,directory,*,originals,allow_large,entropy,limits=Limits()):
        require(sys.flags.optimize==0,'unoptimized constructor only')
        require(sys.dont_write_bytecode,'bytecode-free constructor invocation (-B)')
        require(type(allow_large) is bool and allow_large,'explicit large handoff')
        require(callable(entropy) and type(limits) is Limits,'closed constructor inputs')
        self.limits=limits.validate();self.directory=output_preflight(directory)
        self.originals=safe(Path(originals).absolute())
        require(self.originals.is_dir(),'existing exact originals directory')
        self.before=source_snapshot();self.entropy=Bits(entropy)
        self.output=None;self.memory=None;self.setup_owner=None;self.read_observations={}
        self.outcome=None;self.busy=False;self.closed=False;self.retention_errors=[];self.owner_retention_started=False

    def _reference(self,shared,path,digest,authority=None):
        # Called only with the code-selected historical digest or exact locally
        # derived digest. No public chosen-parameter/descriptor entry is added.
        return shared._reference(path,digest,authority,allow_large=True,resource_curve=1,
                                 writer=self.output.write,saver=self.output.save,
                                 before_import=self._before_import)

    def _before_import(self):
        require(source_snapshot()==self.before,'source changed before private import')
        self.output.verify();self.memory.checkpoint()

    def _construct(self):
        bounded,raw,parameters,public_setup,shared=modules()
        self.memory=bounded.TracedMemory(self.limits.memory_bytes)
        # No reservation is charged to TracedMemory: it has no such API.
        # The existing Limits.validate reservation is one arithmetic component.
        selected=bounded.Limits(max_k=16,contexts=65538,queries=262144,entries=262144,
            requests=1,memory_bytes=self.limits.memory_bytes,output_bytes=4194372,allow_large=True).validate()
        require(selected.reservation()==SETUP_RESERVATION and
                selected.reservation()+CASE_ALLOWANCE==self.limits.memory_bytes,'one logical allowance equation')
        d_raw=read_original(self.originals/D[1],D,self.memory.checkpoint,observation=self.read_observations.setdefault('descriptor',{}))
        key=read_original(self.originals/V[1],V,self.memory.checkpoint,observation=self.read_observations.setdefault('verifying_key',{}))
        self.output.write(self.directory/'historical-descriptor.norito',d_raw)
        self.output.write(self.directory/'historical-vk.bin',key)
        old=self._reference(shared,self.directory/'historical-reference',D[1])
        d=old['descriptor'].Descriptor.decode(d_raw,2);check_profile(d)
        old['verify'].key_points(d,key)
        original=read_original(self.originals/PK[1],PK,self.memory.checkpoint,observation=self.read_observations.setdefault('proving_key',{}))
        self.output.write(self.directory/'historical-public-original.bin',original)
        public=public_setup.PublicSetup.decode(original,d,key,PK[1]);self.memory.checkpoint()
        self.setup_owner=bounded.Owner(raw,parameters,self.entropy,selected,memory=self.memory)
        chosen=self.setup_owner.derive(1,16)
        self.memory.checkpoint()
        # Default owner returns immutable tuple logs; copy dictionary containers
        # before handing the value to the common mechanism, never accept foreign logs.
        from dataclasses import replace
        chosen=replace(chosen,logs={name:tuple(value) if type(value) is tuple else value
                                    for name,value in chosen.logs.items()})
        expected={'descriptor':D[1],'key':V[1],'original':PK[1]}
        case=shared._finish_case(self.directory,d_raw,d,key,original,expected,chosen,old,public,
            reference_factory=lambda path,digest,authority:self._reference(shared,path,digest,authority),
            writer=self.output.write,saver=self.output.save,checkpoint=self.memory.checkpoint)
        self.memory.checkpoint()
        return case

    def _retain_owner(self):
        owner=self.setup_owner
        if owner is None:return
        require(not self.owner_retention_started,'owner retention already attempted')
        self.owner_retention_started=True
        # Existing Owner.persist is intentionally not used: this tree owner must
        # charge aggregate bytes/files/depth before every write, including failure.
        def rows(name,values):
            with self.output.stream(self.directory/name) as emit:
                for value in values:
                    raw=(json.dumps(value,sort_keys=True)+'\n').encode()
                    for i in range(0,len(raw),CHUNK):emit(raw[i:i+CHUNK])
        rows('raw-table-private.jsonl',({'input':k.hex(),'answer':v.hex()} for k,v in owner.oracle.table.items()))
        rows('context-logs-private.jsonl',({'curve':t,'message':m.hex(),'scalar':v} for (t,m),v in owner.oracle.logs.items()))
        rows('sampler-attempts-private.jsonl',iter(owner.sampler.records))
        self.output.save(self.directory/'owner-state.json',{
            'owner_stopped':owner.stopped,'oracle_stopped':owner.oracle.stopped,'requests':owner.requests,
            'rejected_request':getattr(owner,'rejected_request',None),'queries':owner.oracle.queries,
            'contexts':len(owner.oracle.logs),'entries':len(owner.oracle.table),'entropy_calls':self.entropy.calls,
            'private_state_only':True,'family_resamples':0})

    def build(self):
        require(not self.busy,'atomic constructor build')
        if self.outcome is not None:return self.outcome
        require(not self.closed,'constructor closed')
        self.busy=True
        try:
            require(source_snapshot()==self.before,'source changed before build')
            self.output=Outputs(self.directory,self.limits)
            case=self._construct()
            self._retain_owner()
            inventory=self.output.verify()
            self.output.save(self.directory/'construction.json',{
                'status':'prepared; success requires returned Outcome and no failure.json',
                'scope':'chosen outer A1 only; no recursive/source/native authority',
                'chosen_descriptor':sha(case.descriptor.raw),'chosen_key':sha(case.key),
                'chosen_original':sha(case.public_original),'chosen_params':sha(case.raw_params),
                'traced_allocations':self.memory.observe(),'logical_setup_allowance':SETUP_RESERVATION,
                'logical_case_allowance':CASE_ALLOWANCE,'allocation_ceiling':self.limits.memory_bytes,
                'same_tracer_for_intake_setup_rebind':True,'source_pins':self.before,
                'original_reads':self.read_observations},terminal=True)
            inventory=self.output.verify()
            self.output.save(self.directory/'inventory.json',{'entries':inventory,
                'self_excluded':'inventory.json; its own byte/hash is checked by the live output ledger before return'},terminal=True)
            self.output.verify()
            require(source_snapshot()==self.before,'source changed after retention')
            self.memory.checkpoint()
            self.outcome=Outcome(case,None)
            return self.outcome
        except BaseException as error:
            self.outcome=Outcome(None,type(error).__name__+': '+str(error)[:1024])
            if self.output is not None:
                # Partial retained files remain DATA. Never retry persistence over
                # occupied names; preserve the first failure and report retention failure.
                try:
                    if self.setup_owner is not None and not self.owner_retention_started:
                        self._retain_owner()
                except BaseException as exc:self.retention_errors.append(type(exc).__name__+': '+str(exc)[:1024])
                try:self.output.save(self.directory/'failure.json',{'error':self.outcome.error,
                    'retention_errors':self.retention_errors,'success':False,'entropy_calls':self.entropy.calls,
                    'allocations':self.memory.observe() if self.memory else None,
                    'original_reads':self.read_observations},terminal=True)
                except BaseException as exc:self.retention_errors.append(type(exc).__name__+': '+str(exc)[:1024])
            if self.memory is not None:self.memory.close()
            self.closed=True
            if not isinstance(error,Exception):raise
            return self.outcome
        finally:self.busy=False

    def query(self,data):
        """Same residual raw oracle after success, with its remaining finite caps."""
        require(not self.busy and not self.closed and self.outcome is not None and self.outcome.case is not None,
                'completed live constructor required')
        return self.setup_owner.query(data)

    def close(self):
        """End local residual use; no restart, new sampler or deserialized trust."""
        require(not self.busy,'atomic constructor close')
        if not self.closed:
            self.closed=True
            if self.memory is not None:self.memory.close()

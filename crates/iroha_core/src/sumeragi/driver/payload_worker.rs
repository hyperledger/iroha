//! Bounded worker-owned payload jobs. Every retry keeps the original funded phase.
//! Core receives custody only after authoring, reconstruction, or complete stored restoration.

use super::{
    acquisition::{StoredAcquisition, StoredError, StoredProgress},
    payload_jobs::{AuthorJob, NetworkAcquisition, PayloadDissemination},
    traits::{BlockStore, BodyStore, Net},
};
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::durable_artifact::BodyReadError;
use iroha_allocation::AllocationBudget;
use iroha_primitives::erasure::rs16::compact::{CodecAllocationError, Encoded};
use iroha_sumeragi::{
    api::{Action, Event},
    availability::{AuthoringError, AvailabilitySource, AvailableBody, PayloadBytes},
    crypto::{Crypto, Signer},
    message::{BlockHeader, PayloadChunk, PayloadManifest, PayloadRequest, WireMessage},
    types::{Hash32, HeightConfig, PublicKey},
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::Arc,
};

type Key = (u64, Hash32);

/// One command from Core, or a bounded retry requested by the worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayloadWork {
    /// Author exactly the selected statement with the selected local key.
    Author {
        /// Current Core authoring request identity.
        req: u64,
        /// Independently authenticated configuration for this exact height.
        config: HeightConfig,
        /// Exact header template selected by Core before authoring.
        header: BlockHeader,
        /// Original-pool canonical payload selected by the builder.
        payload: PayloadBytes,
    },
    /// Obtain custody from actual authenticated rows.
    Acquire {
        /// Immutable expected instance, height, block and complete authority.
        source: AvailabilitySource,
        /// Original signed availability carrier to verify.
        manifest: PayloadManifest,
    },
    /// Deliver one admitted relay row to the matching retained job.
    Chunk {
        /// Authenticated transport sender retained through local resource refusal.
        from: PublicKey,
        /// Exact original relay row to authenticate and admit.
        chunk: PayloadChunk,
    },
    /// Disseminate an already available body after Core's durable-body barrier.
    Disseminate {
        /// Authenticated destination peers.
        peers: Vec<PublicKey>,
        /// Opaque custody of the exact verified payload and original signature table.
        body: AvailableBody,
    },
    /// Restore locally before requesting rows from remote peers.
    Fetch {
        /// Immutable expected instance, height, block and complete authority.
        source: AvailabilitySource,
        /// Authenticated destination peers.
        peers: Vec<PublicKey>,
    },
    /// Serve original signed evidence and actual rows from independently resolved history.
    Serve {
        /// Authenticated requesting peer.
        to: PublicKey,
        /// Requested committed or unapplied height.
        height: u64,
        /// Exact requested block identity.
        block_hash: Hash32,
    },
    /// Release obsolete acquisition and author work after application advances.
    Applied(u64),
    /// Keep only Core's current proactive body cache at this height; historical responses
    /// have independent request lifetimes and are unaffected.
    Retain {
        /// Height whose proactive cache Core trimmed.
        height: u64,
        /// Exact still-referenced body identities.
        keep: Vec<Hash32>,
    },
    /// Progress retained jobs without replacing their original owners.
    Poll,
}

impl PayloadWork {
    /// Convert only payload actions; return every other action unchanged.
    pub fn from_action(action: Action) -> Result<Self, Action> {
        match action {
            Action::AuthorPayload {
                req,
                config,
                header,
                payload,
            } => Ok(Self::Author {
                req,
                config,
                header,
                payload,
            }),
            Action::AcquirePayload { source, manifest } => Ok(Self::Acquire { source, manifest }),
            Action::ReceivePayloadChunk { from, chunk } => Ok(Self::Chunk { from, chunk }),
            Action::DisseminatePayload { peers, body } => Ok(Self::Disseminate { peers, body }),
            Action::FetchPayload { source, peers } => Ok(Self::Fetch { source, peers }),
            Action::ServePayload {
                to,
                height,
                block_hash,
            } => Ok(Self::Serve {
                to,
                height,
                block_hash,
            }),
            other => Err(other),
        }
    }
}

/// A bounded worker turn; sends are emitted by the host before reporting completion.
#[derive(Default)]
pub struct PayloadProgress {
    /// Verified completion or a proven original-manifest fault.
    pub events: Vec<Event>,
    /// Local refusal or another bounded output row needs a later worker turn.
    pub retry: bool,
    /// A retained resource refusal requires bounded backoff before retry.
    pub refused: bool,
    /// Bytes admitted this turn to metered recipients; pending frames contribute zero.
    pub charges: Vec<(PublicKey, u64)>,
}

struct Author {
    source: AvailabilitySource,
    signer: Arc<dyn Signer>,
    job: AuthorJob,
}
struct Authored {
    source: AvailabilitySource,
    body: AvailableBody,
    codeword: Encoded,
}
struct Incoming {
    source: AvailabilitySource,
    job: NetworkAcquisition,
    runnable: bool,
}
enum ReadPurpose {
    Fetch(Vec<PublicKey>),
    Serve(PublicKey),
}
struct Read {
    source: AvailabilitySource,
    purpose: ReadPurpose,
    job: Option<StoredAcquisition>,
    committed: bool,
    retired: bool,
    remote_ready: bool,
    delivery: Option<super::serve::DeliveryBatch>,
    refusal: Option<crate::execution_attempt::ExecutionDeferred>,
}
struct RecipientStream {
    peer: PublicKey,
    next: usize,
    delivery: Option<super::serve::DeliveryBatch>,
    complete: bool,
}
impl RecipientStream {
    fn new(peer: PublicKey) -> Self {
        Self {
            peer,
            next: 0,
            delivery: None,
            complete: false,
        }
    }
}
struct Outgoing {
    source: AvailabilitySource,
    peers: VecDeque<RecipientStream>,
    job: PayloadDissemination,
    manifest_frame: Option<super::traits::Frame>,
    row_frame: Option<(usize, super::traits::Frame)>,
    active: bool,
    metered: bool,
}

/// One instance's bounded, retained work, owned exclusively by its worker thread.
/// No source is authorized by the body currently being decoded.
pub struct PayloadWorker {
    instance: Hash32,
    budget: AllocationBudget,
    crypto: Arc<dyn Crypto + Send + Sync>,
    signers: Vec<Arc<dyn Signer>>,
    max_jobs: usize,
    author: Option<Author>,
    authored: Option<Authored>,
    incoming: BTreeMap<Key, Incoming>,
    incoming_cursor: Option<Key>,
    reads: VecDeque<Read>,
    deferred: VecDeque<(
        PayloadWork,
        Option<crate::execution_attempt::ExecutionDeferred>,
    )>,
    outgoing: VecDeque<Outgoing>,
    applied: u64,
    next_acquisition: u64,
    pub(super) metadata: VecDeque<(PublicKey, super::serve::DeliveryBatch)>,
}

fn fault(message: impl std::fmt::Debug) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("availability worker: {message:?}"),
    )
}
fn source_key(source: &AvailabilitySource) -> Key {
    (source.height(), source.block_hash())
}
fn author_refusal(error: &AuthoringError) -> bool {
    match error {
        AuthoringError::Bytes(error) => error.is_local_refusal(),
        AuthoringError::Codec(
            CodecAllocationError::Admission(_) | CodecAllocationError::Allocation(_),
        ) => true,
        _ => false,
    }
}
fn read_refusal(error: &StoredError) -> bool {
    match error {
        StoredError::Read(BodyReadError::Deferred(_)) => true,
        StoredError::Read(BodyReadError::Io(error)) => matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ),
        StoredError::Read(BodyReadError::Admission(error)) => error.is_local_refusal(),
        StoredError::Restoration(error) => error.is_local_refusal(),
        _ => false,
    }
}

fn stored_refusal(error: StoredError) -> Option<crate::execution_attempt::ExecutionDeferred> {
    let error = match error {
        StoredError::Read(error) => error.into_attempt(),
        StoredError::Restoration(error) => super::super::storage_attempt::restoration(error),
        StoredError::Source | StoredError::Completed => return None,
    };
    super::super::storage_attempt::take_deferred(error).ok()
}

impl PayloadWorker {
    /// Bind the original allocation owner and immutable instance once at startup.
    pub fn new(
        instance: Hash32,
        budget: AllocationBudget,
        crypto: Arc<dyn Crypto + Send + Sync>,
        signers: Vec<Arc<dyn Signer>>,
        max_jobs: usize,
        applied: u64,
    ) -> Self {
        Self {
            instance,
            budget,
            crypto,
            signers,
            max_jobs: max_jobs.max(1),
            author: None,
            authored: None,
            incoming: BTreeMap::new(),
            incoming_cursor: None,
            reads: VecDeque::new(),
            deferred: VecDeque::new(),
            outgoing: VecDeque::new(),
            applied,
            next_acquisition: 1,
            metadata: VecDeque::new(),
        }
    }

    /// Accept a command and make bounded progress. Corruption and violated local contracts
    /// stop the worker; neither can masquerade as an absent body or a successful read.
    pub fn step(
        &mut self,
        work: PayloadWork,
        bodies: &dyn BodyStore,
        blocks: &dyn BlockStore,
        net: &dyn Net,
    ) -> io::Result<PayloadProgress> {
        let mut progress = PayloadProgress::default();
        self.accept(work, blocks)?;
        if let Some((work, refusal)) = self.deferred.pop_front() {
            self.accept(work, blocks)?;
            drop(refusal);
        }
        progress.refused |= !self.deferred.is_empty();
        self.author(&mut progress)?;
        self.receive(&mut progress)?;
        self.read(bodies, blocks, net, &mut progress)?;
        self.send(net, &mut progress)?;
        progress.retry |= self.has_runnable();
        Ok(progress)
    }

    /// Whether a bounded poll can progress retained work; waiting for remote rows is excluded.
    pub(super) fn has_runnable(&self) -> bool {
        self.author.is_some()
            || self.incoming.values().any(|job| job.runnable)
            || !self.reads.is_empty()
            || !self.deferred.is_empty()
            || self.outgoing.iter().any(|job| job.active)
            || !self.metadata.is_empty()
    }

    // Each purpose has its own finite slot quota so a permanently refused peer in one
    // class cannot prevent progress in the other. All bulk backing shares the original pool.
    fn make_outgoing_room(&mut self, metered: bool) {
        if self
            .outgoing
            .iter()
            .filter(|job| job.metered == metered)
            .count()
            >= self.max_jobs
        {
            let index = self
                .outgoing
                .iter()
                .position(|job| job.metered == metered && !job.active)
                .or_else(|| self.outgoing.iter().position(|job| job.metered == metered))
                .expect("full purpose quota");
            // Cancel exactly the oldest retained occurrence in this purpose. Its durable
            // source remains servable; new authorized work cannot be refused forever.
            self.outgoing.remove(index);
        }
    }

    pub(super) fn retain_metadata(
        &mut self,
        peer: PublicKey,
        delivery: super::serve::DeliveryBatch,
    ) {
        self.metadata.retain(|(existing, _)| existing != &peer);
        if self.metadata.len() >= self.max_jobs {
            self.metadata.pop_front(); // O6: bounded oldest response cancellation.
        }
        self.metadata.push_back((peer, delivery));
    }

    fn accept(&mut self, work: PayloadWork, blocks: &dyn BlockStore) -> io::Result<()> {
        match work {
            PayloadWork::Author {
                req,
                config,
                header,
                payload,
            } => {
                if header.height <= self.applied
                    || self.author.as_ref().is_some_and(|a| a.job.req == req)
                {
                    return Ok(());
                }
                let signer_key = config
                    .committee
                    .get(header.proposer)
                    .ok_or_else(|| fault("author index"))?;
                let signer = self
                    .signers
                    .iter()
                    .find(|s| s.public_key() == signer_key)
                    .cloned()
                    .ok_or_else(|| fault("missing selected author key"))?;
                let source = AvailabilitySource::new(
                    self.instance,
                    header.height,
                    header.hash(&*self.crypto),
                    config.clone(),
                )
                .map_err(fault)?;
                self.author = Some(Author {
                    source,
                    signer,
                    job: AuthorJob::new(req, config, header, payload),
                });
                self.authored = None;
            }
            PayloadWork::Acquire { source, manifest } => {
                if source.instance() != self.instance {
                    return Err(fault("foreign acquisition instance"));
                }
                if source.height() <= self.applied {
                    return Ok(());
                }
                let key = source_key(&source);
                if let Some(job) = self.incoming.get(&key) {
                    // A retransmission cannot reset received rows or the retained refused row.
                    // Another untrusted table for this identity does not displace that owner.
                    if !job.job.matches(&source, &manifest) {
                        return Ok(());
                    }
                } else if self.incoming.len() < self.max_jobs {
                    let audit_id = self.next_acquisition;
                    self.next_acquisition = audit_id
                        .checked_add(1)
                        .ok_or_else(|| fault("acquisition identity exhausted"))?;
                    self.incoming.insert(
                        key,
                        Incoming {
                            source: source.clone(),
                            job: NetworkAcquisition::new(source, manifest, audit_id),
                            runnable: true,
                        },
                    );
                }
            }
            PayloadWork::Chunk { from, chunk } => {
                if chunk.instance != self.instance {
                    return Err(fault("foreign relay instance"));
                }
                if let Some(job) = self.incoming.get_mut(&(chunk.height, chunk.block_hash)) {
                    // O6 drops only the newly arriving row when the original retry slot is full.
                    if job.job.receive(from, chunk).is_ok() {
                        job.runnable = true;
                    }
                }
            }
            PayloadWork::Disseminate { mut peers, body } => {
                peers.retain(|peer| !self.signers.iter().any(|s| s.public_key() == peer));
                if peers.is_empty() {
                    return Ok(());
                }
                if body.source().instance() != self.instance {
                    return Err(fault("foreign dissemination custody"));
                }
                if body.source().height() <= self.applied {
                    return Ok(());
                }
                let key = (body.header().height, body.hash(&*self.crypto));
                if let Some(job) = self.outgoing.iter_mut().find(|j| {
                    !j.metered
                        && source_key(&j.source) == key
                        && j.peers.len() == peers.len()
                        && j.peers.iter().all(|p| peers.contains(&p.peer))
                }) {
                    if !job.active {
                        for peer in &mut job.peers {
                            peer.next = 0;
                            peer.complete = false;
                        }
                        job.active = true;
                    }
                    return Ok(());
                }
                self.make_outgoing_room(false);
                let authored = self.authored.take();
                let (source, codeword) = match authored {
                    Some(authored)
                        if source_key(&authored.source) == key
                            && authored.body.availability() == body.availability() =>
                    {
                        (authored.source, Some(authored.codeword))
                    }
                    other => {
                        self.authored = other;
                        (body.source().clone(), None)
                    }
                };
                self.outgoing.push_back(Outgoing {
                    source: source.clone(),
                    peers: peers.into_iter().map(RecipientStream::new).collect(),
                    job: PayloadDissemination::new(source, body, codeword),
                    manifest_frame: None,
                    row_frame: None,
                    active: true,
                    metered: false,
                });
            }
            PayloadWork::Fetch { source, mut peers } => {
                peers.retain(|peer| !self.signers.iter().any(|s| s.public_key() == peer));
                if source.instance() != self.instance {
                    return Err(fault("foreign fetch instance"));
                }
                if let Some(job) = self.reads.iter_mut().find(|job| {
                    job.source == source && matches!(job.purpose, ReadPurpose::Fetch(_))
                }) {
                    if let Some(delivery) = &mut job.delivery {
                        delivery.retarget(&peers);
                    }
                    job.purpose = ReadPurpose::Fetch(peers);
                    return Ok(());
                }
                if self
                    .reads
                    .iter()
                    .filter(|job| matches!(job.purpose, ReadPurpose::Fetch(_)))
                    .count()
                    >= self.max_jobs
                {
                    let index = self
                        .reads
                        .iter()
                        .position(|job| matches!(job.purpose, ReadPurpose::Fetch(_)))
                        .expect("full local recovery quota");
                    self.reads.remove(index);
                }
                self.reads.push_front(Read {
                    source,
                    purpose: ReadPurpose::Fetch(peers),
                    job: None,
                    committed: false,
                    retired: false,
                    remote_ready: false,
                    delivery: None,
                    refusal: None,
                });
            }
            PayloadWork::Serve {
                to,
                height,
                block_hash,
            } => {
                if self.signers.iter().any(|s| s.public_key() == &to) {
                    return Ok(());
                }
                if self.reads.iter().any(|job| {
                    matches!(&job.purpose, ReadPurpose::Serve(peer) if peer == &to)
                        && job.source.height() == height
                        && job.source.block_hash() == block_hash
                }) || self.outgoing.iter().any(|job| {
                    job.metered
                        && job.active
                        && job.peers.iter().any(|peer| peer.peer == to)
                        && job.source.height() == height
                        && job.source.block_hash() == block_hash
                }) {
                    return Ok(());
                }
                // The newest historical request supersedes only this recipient's response.
                self.reads
                    .retain(|job| !matches!(&job.purpose, ReadPurpose::Serve(peer) if peer == &to));
                self.outgoing
                    .retain(|job| !(job.metered && job.peers.iter().any(|peer| peer.peer == to)));
                if self
                    .reads
                    .iter()
                    .filter(|job| matches!(job.purpose, ReadPurpose::Serve(_)))
                    .count()
                    >= self.max_jobs
                {
                    let index = self
                        .reads
                        .iter()
                        .position(|job| matches!(job.purpose, ReadPurpose::Serve(_)))
                        .expect("full historical quota");
                    self.reads.remove(index);
                }
                // This authority is selected before opening either stored artifact.
                let source = match blocks.availability_source(height, block_hash) {
                    Ok(Some(source)) => source,
                    Ok(None) => return Ok(()),
                    Err(Attempt::Deferred(reason)) => {
                        self.defer(
                            PayloadWork::Serve {
                                to,
                                height,
                                block_hash,
                            },
                            Some(reason),
                        );
                        return Ok(());
                    }
                    Err(Attempt::Rejected(error))
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        self.defer(
                            PayloadWork::Serve {
                                to,
                                height,
                                block_hash,
                            },
                            None,
                        );
                        return Ok(());
                    }
                    Err(Attempt::Rejected(error)) => return Err(error),
                };
                if source.instance() != self.instance {
                    return Err(fault("foreign historical schedule"));
                }
                self.reads.push_back(Read {
                    source,
                    purpose: ReadPurpose::Serve(to),
                    job: None,
                    committed: false,
                    retired: false,
                    remote_ready: false,
                    delivery: None,
                    refusal: None,
                });
            }
            PayloadWork::Retain { height, keep } => {
                self.outgoing.retain(|job| {
                    job.metered
                        || job.source.height() != height
                        || keep.contains(&job.source.block_hash())
                });
                if self.authored.as_ref().is_some_and(|job| {
                    job.source.height() == height && !keep.contains(&job.source.block_hash())
                }) {
                    self.authored = None;
                }
            }
            PayloadWork::Applied(height) => {
                self.applied = self.applied.max(height);
                self.incoming
                    .retain(|_, job| job.source.height() > self.applied);
                self.outgoing
                    .retain(|j| j.source.height() > self.applied || (j.metered && j.active));
                if self
                    .author
                    .as_ref()
                    .is_some_and(|j| j.source.height() <= self.applied)
                {
                    self.author = None;
                }
                if self
                    .authored
                    .as_ref()
                    .is_some_and(|j| j.source.height() <= self.applied)
                {
                    self.authored = None;
                }
                self.reads.retain(|j| {
                    j.source.height() > self.applied || matches!(j.purpose, ReadPurpose::Serve(_))
                });
            }
            PayloadWork::Poll => {}
        }
        Ok(())
    }

    fn defer(
        &mut self,
        work: PayloadWork,
        refusal: Option<crate::execution_attempt::ExecutionDeferred>,
    ) {
        if let Some((_, retained)) = self
            .deferred
            .iter_mut()
            .find(|(pending, _)| *pending == work)
        {
            *retained = refusal;
        } else if self.deferred.len() < self.max_jobs {
            self.deferred.push_back((work, refusal));
        }
    }

    fn author(&mut self, progress: &mut PayloadProgress) -> io::Result<()> {
        let Some(mut author) = self.author.take() else {
            return Ok(());
        };
        match author
            .job
            .poll(&self.budget, &*self.crypto, &*author.signer)
        {
            Ok(authored) => {
                // Authoring fills the availability digest; bind the final signed identity.
                let source = authored.body.source().clone();
                if source.config() != author.source.config() || source.instance() != self.instance {
                    return Err(fault("author changed original authority"));
                }
                available_audit(&authored.body, "author", (0, 0));
                progress.events.push(Event::PayloadAuthored {
                    req: author.job.req,
                    body: authored.body.clone(),
                });
                self.authored = Some(Authored {
                    source,
                    body: authored.body,
                    codeword: authored.codeword,
                });
            }
            Err(AuthoringError::SigningFailed {
                kind,
                height,
                view,
                error,
            }) => {
                progress.events.push(Event::SigningFailed {
                    kind,
                    height,
                    view,
                    error,
                });
                self.author = Some(author);
                progress.retry = true;
                progress.refused = true;
            }
            Err(error) if author_refusal(&error) => {
                self.author = Some(author);
                progress.retry = true;
                progress.refused = true;
            }
            Err(error) => return Err(fault(error)),
        }
        Ok(())
    }

    fn receive(&mut self, progress: &mut PayloadProgress) -> io::Result<()> {
        // Round-robin across runnable identities, so a refused early key cannot starve later rows.
        let key = self
            .incoming
            .iter()
            .filter(|(_, j)| j.runnable)
            .map(|(k, _)| *k)
            .find(|k| self.incoming_cursor.is_none_or(|last| *k > last))
            .or_else(|| {
                self.incoming
                    .iter()
                    .find(|(_, j)| j.runnable)
                    .map(|(k, _)| *k)
            });
        let Some(key) = key else {
            return Ok(());
        };
        self.incoming_cursor = Some(key);
        let mut incoming = self
            .incoming
            .remove(&key)
            .expect("selected original acquisition");
        match incoming.job.poll(&self.budget, &*self.crypto) {
            Ok(block) => {
                available_audit(&block, "network_rows", incoming.job.audit());
                progress.events.push(Event::BodyAvailable { block });
            }
            Err(error) if error.rejects_manifest() => {
                if let Some(manifest) = incoming.job.manifest() {
                    progress.events.push(Event::ManifestRejected {
                        manifest: manifest.clone(),
                    });
                }
            }
            Err(error) => {
                incoming.runnable = error.is_local_refusal();
                progress.refused |= incoming.runnable;
                self.incoming.insert(key, incoming);
            }
        }
        Ok(())
    }

    fn read(
        &mut self,
        bodies: &dyn BodyStore,
        blocks: &dyn BlockStore,
        net: &dyn Net,
        progress: &mut PayloadProgress,
    ) -> io::Result<()> {
        let Some(mut read) = self.reads.pop_front() else {
            return Ok(());
        };
        if read.remote_ready {
            if read.delivery.is_none() {
                let ReadPurpose::Fetch(peers) = &read.purpose else {
                    unreachable!("only fetch has remote output")
                };
                let message = WireMessage::PayloadRequest(PayloadRequest {
                    instance: self.instance,
                    height: read.source.height(),
                    block_hash: read.source.block_hash(),
                });
                let frame = super::serve::frame(&message)
                    .ok_or_else(|| fault("payload request encoding"))?;
                read.delivery = Some(super::serve::DeliveryBatch::new(
                    vec![(peers.clone(), frame)],
                    &[],
                )?);
            }
            let delivery = read
                .delivery
                .as_mut()
                .expect("original source-bound request");
            progress.charges.extend(delivery.poll(net)?);
            if !delivery.complete() {
                progress.refused = true;
                self.reads.push_back(read);
            }
            return Ok(());
        }
        if read.committed {
            return self.read_committed(read, blocks, progress);
        }
        if read.job.is_none() {
            match StoredAcquisition::begin(bodies, read.source.clone()) {
                Ok(job) => read.job = Some(job),
                Err(error) if read_refusal(&error) => {
                    read.refusal = stored_refusal(error);
                    self.reads.push_back(read);
                    progress.retry = true;
                    progress.refused = true;
                    return Ok(());
                }
                Err(error) => return Err(fault(error)),
            }
        }
        match read
            .job
            .as_mut()
            .expect("retained original storage job")
            .poll(&self.budget, &*self.crypto)
        {
            Ok(StoredProgress::Available(block)) => self.read_available(read, block, progress),
            Ok(StoredProgress::Absent) => {
                read.committed = true;
                read.job = None;
                self.reads.push_back(read);
            }
            Ok(StoredProgress::Pending(error)) => {
                read.refusal = super::super::storage_attempt::take_deferred(
                    super::super::storage_attempt::byte(error),
                )
                .ok();
                self.reads.push_back(read);
                progress.retry = true;
                progress.refused = true;
            }
            Err(StoredError::Read(BodyReadError::Io(ref error)))
                if error.kind() == io::ErrorKind::NotFound
                    && !read.committed
                    && bodies.retirement_authorized(read.source.height()) =>
            {
                // The persistence worker applied and retired this height while the
                // original file read was in flight. Preserve immutable authority,
                // but reacquire and verify all bytes from committed storage. Other
                // path changes, corruption and refusals remain errors or exact retries.
                read.committed = true;
                read.retired = true;
                read.job = None;
                self.reads.push_back(read);
            }
            Err(error) if read_refusal(&error) => {
                read.refusal = stored_refusal(error);
                self.reads.push_back(read);
                progress.retry = true;
                progress.refused = true;
            }
            Err(error) => return Err(fault(error)),
        }
        Ok(())
    }

    fn read_committed(
        &mut self,
        mut read: Read,
        blocks: &dyn BlockStore,
        progress: &mut PayloadProgress,
    ) -> io::Result<()> {
        match blocks.committed_body(read.source.height()) {
            Ok(Some((block, _qc))) => {
                let actual = block.source();
                if actual.instance() != read.source.instance()
                    || actual.height() != read.source.height()
                    || actual.config() != read.source.config()
                    || !block.admitted_to(&self.budget)
                {
                    return Err(fault(
                        "committed lookup changed authority or allocation owner",
                    ));
                }
                // A fully authenticated canonical block may supersede the requested
                // proposal. Cancel only that stale lookup; never return the other
                // block as custody for the requested hash. The same verified owner
                // supplies a matching lookup without a second read or projection.
                if actual.block_hash() == read.source.block_hash() {
                    self.read_available(read, block, progress);
                }
            }
            Ok(None) if read.retired => {
                return Err(fault("retired body is missing from committed storage"));
            }
            Ok(None) => {
                if matches!(read.purpose, ReadPurpose::Fetch(_)) {
                    read.remote_ready = true;
                    self.reads.push_back(read);
                }
            }
            Err(Attempt::Deferred(reason)) => {
                read.refusal = Some(reason);
                self.reads.push_back(read);
                progress.retry = true;
                progress.refused = true;
            }
            Err(Attempt::Rejected(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.reads.push_back(read);
                progress.retry = true;
                progress.refused = true;
            }
            Err(Attempt::Rejected(error)) => return Err(error),
        }
        Ok(())
    }

    fn read_available(&mut self, read: Read, block: AvailableBody, progress: &mut PayloadProgress) {
        match read.purpose {
            ReadPurpose::Fetch(_) => progress.events.push(Event::BodyAvailable { block }),
            ReadPurpose::Serve(to) => {
                self.make_outgoing_room(true);
                self.outgoing.push_back(Outgoing {
                    source: read.source.clone(),
                    peers: VecDeque::from([RecipientStream::new(to)]),
                    job: PayloadDissemination::new(read.source, block, None),
                    manifest_frame: None,
                    row_frame: None,
                    active: true,
                    metered: true,
                });
            }
        }
    }

    fn send(&mut self, net: &dyn Net, progress: &mut PayloadProgress) -> io::Result<()> {
        let Some(index) = self.outgoing.iter().position(|job| job.active) else {
            return Ok(());
        };
        let mut outgoing = self
            .outgoing
            .remove(index)
            .expect("active original outgoing owner");
        let pending_index = outgoing.job.pending_index();
        let selected = outgoing.peers.iter().position(|peer| {
            !peer.complete
                && (peer.delivery.is_some()
                    || peer.next == 0
                    || pending_index.is_none_or(|index| peer.next - 1 == index))
        });
        if let Some(index) = selected {
            let mut peer = outgoing
                .peers
                .remove(index)
                .expect("bounded recipient cursor");
            if peer.delivery.is_none() {
                let frame = if peer.next == 0 {
                    if outgoing.manifest_frame.is_none() {
                        outgoing.manifest_frame = Some(
                            super::serve::frame(&WireMessage::PayloadManifest(
                                outgoing.job.manifest(),
                            ))
                            .ok_or_else(|| fault("manifest encoding"))?,
                        );
                    }
                    Some(
                        outgoing
                            .manifest_frame
                            .as_ref()
                            .expect("encoded original manifest")
                            .clone(),
                    )
                } else {
                    if let Some((index, frame)) = &outgoing.row_frame
                        && *index == peer.next - 1
                    {
                        Some(frame.clone())
                    } else {
                        match outgoing
                            .job
                            .chunk(peer.next - 1, &self.budget, &*self.crypto)
                        {
                            Ok(Some(chunk)) => {
                                let frame = super::serve::frame(&WireMessage::PayloadChunk(chunk))
                                    .ok_or_else(|| fault("signed row encoding"))?;
                                outgoing.row_frame = Some((peer.next - 1, frame.clone()));
                                Some(frame)
                            }
                            Ok(None) => {
                                peer.complete = true;
                                None
                            }
                            Err(error) if error.is_local_refusal() => {
                                progress.refused = true;
                                None
                            }
                            Err(error) => return Err(fault(error)),
                        }
                    }
                };
                if let Some(frame) = frame {
                    let metered = if outgoing.metered {
                        vec![peer.peer.clone()]
                    } else {
                        vec![]
                    };
                    peer.delivery = Some(super::serve::DeliveryBatch::new(
                        vec![(vec![peer.peer.clone()], frame)],
                        &metered,
                    )?);
                }
            }
            if let Some(mut delivery) = peer.delivery.take() {
                progress.charges.extend(delivery.poll(net)?);
                if delivery.complete() {
                    peer.next += 1;
                } else {
                    peer.delivery = Some(delivery);
                    progress.refused = true;
                }
            }
            outgoing.peers.push_back(peer);
        }
        outgoing.active = outgoing.peers.iter().any(|peer| !peer.complete);
        if outgoing.active || outgoing.source.height() > self.applied {
            self.outgoing.push_back(outgoing);
        }
        Ok(())
    }
}

/// This observation is emitted only after actual authoring or network reconstruction succeeds.
/// It is local experiment provenance; certificate verification supplies cryptographic authority.
fn available_audit(body: &AvailableBody, origin: &'static str, acquisition: (u64, u32)) {
    let header = body.header();
    iroha_logger::info!(
        process_id = std::process::id(),
        instance = %body.source().instance(),
        height = body.source().height(),
        block = %body.source().block_hash(),
        availability_digest = %header.availability_digest,
        payload_hash = %header.payload_hash,
        payload_bytes = header.payload_len,
        origin,
        acquisition = acquisition.0,
        accepted_rows = acquisition.1,
        epoch = body.source().config().epoch.id.epoch,
        context = %body.source().config().epoch.id.context,
        proposer = header.proposer,
        "sumeragi payload custody verified"
    );
}

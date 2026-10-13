//! Fixed physical DNS custody for synchronous archive clients.
//!
//! An expired caller never frees an in-flight resolver slot. Two process-wide workers own
//! native lookups until they return, and at most eight bounded jobs can wait behind them.
//! TODO: Qualify native OS resolver allocations against the complete process RSS envelope on
//! each platform; the OS can allocate internally before Rust can bound answer iteration.

use super::{MAX_DNS_ADDRESSES_PER_HOST, is_public_ip};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::Instant,
};

const WORKERS: usize = 2;
const QUEUED: usize = 8;
const HOST_BYTES: usize = 253;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Busy,
    Deadline,
    Invalid,
    Unavailable,
}

type Answer = Result<Vec<SocketAddr>, Error>;
type Resolver = dyn Fn(&str, u16) -> Answer + Send + Sync;

struct Job {
    host: Box<str>,
    port: u16,
    deadline: Instant,
    reply: mpsc::SyncSender<Answer>,
}

struct Pool {
    jobs: mpsc::SyncSender<Job>,
}

impl Pool {
    fn new(workers: usize, queued: usize, resolver: Arc<Resolver>) -> Result<Self, Error> {
        let (jobs, received) = mpsc::sync_channel::<Job>(queued);
        let received = Arc::new(Mutex::new(received));
        for (index, resolver) in std::iter::repeat_n(resolver, workers).enumerate() {
            let received = received.clone();
            std::thread::Builder::new()
                .name(format!("musubi-dns-{index}"))
                .spawn(move || {
                    loop {
                        let job = {
                            let Ok(queue) = received.lock() else {
                                return;
                            };
                            let Ok(job) = queue.recv() else { return };
                            job
                        };
                        if Instant::now() >= job.deadline {
                            continue;
                        }
                        let answer = resolver(&job.host, job.port).and_then(validate_answers);
                        if Instant::now() < job.deadline {
                            // Abandoned results never block a worker or become another job's answer.
                            let _ = job.reply.try_send(answer);
                        }
                    }
                })
                .map_err(|_| Error::Unavailable)?;
        }
        Ok(Self { jobs })
    }

    fn resolve(&self, host: &str, port: u16, deadline: Instant) -> Answer {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        if host.is_empty() || host.len() > HOST_BYTES || port == 0 {
            return Err(Error::Invalid);
        }
        let (reply, received) = mpsc::sync_channel(1);
        self.jobs
            .try_send(Job {
                host: host.into(),
                port,
                deadline,
                reply,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => Error::Busy,
                mpsc::TrySendError::Disconnected(_) => Error::Unavailable,
            })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Deadline);
        }
        let answer = received
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => Error::Deadline,
                mpsc::RecvTimeoutError::Disconnected if Instant::now() >= deadline => {
                    Error::Deadline
                }
                mpsc::RecvTimeoutError::Disconnected => Error::Unavailable,
            })?;
        if Instant::now() >= deadline {
            Err(Error::Deadline)
        } else {
            answer
        }
    }
}

fn validate_answers(mut answers: Vec<SocketAddr>) -> Answer {
    if answers.is_empty()
        || answers.len() > MAX_DNS_ADDRESSES_PER_HOST
        || answers.iter().any(|answer| !is_public_ip(answer.ip()))
    {
        return Err(Error::Invalid);
    }
    answers.sort_unstable();
    answers.dedup();
    Ok(answers)
}

fn native_resolve(host: &str, port: u16) -> Answer {
    let answers = (host, port)
        .to_socket_addrs()
        .map_err(|_| Error::Unavailable)?;
    // Inspect at most one answer beyond the protocol cap; do not collect an arbitrary iterator.
    Ok(answers.take(MAX_DNS_ADDRESSES_PER_HOST + 1).collect())
}

pub(super) fn resolve(host: &str, port: u16, deadline: Instant) -> Answer {
    static POOL: OnceLock<Result<Pool, Error>> = OnceLock::new();
    if Instant::now() >= deadline {
        return Err(Error::Deadline);
    }
    POOL.get_or_init(|| Pool::new(WORKERS, QUEUED, Arc::new(native_resolve)))
        .as_ref()
        .map_err(|error| *error)?
        .resolve(host, port, deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    fn public() -> SocketAddr {
        "1.1.1.1:443".parse().unwrap()
    }

    #[test]
    fn answers_reject_empty_private_and_excessive_sets_and_deduplicate() {
        assert_eq!(validate_answers(vec![]), Err(Error::Invalid));
        assert_eq!(
            validate_answers(vec![public(), "127.0.0.1:443".parse().unwrap()]),
            Err(Error::Invalid)
        );
        assert_eq!(
            validate_answers(vec![public(); MAX_DNS_ADDRESSES_PER_HOST + 1]),
            Err(Error::Invalid)
        );
        assert_eq!(
            validate_answers(vec![public(), public()]).unwrap(),
            vec![public()]
        );
    }

    #[test]
    fn stalled_native_work_retains_slots_and_expired_queued_work_is_discarded() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Arc::new(Mutex::new(released));
        let counted = calls.clone();
        let pool = Arc::new(
            Pool::new(
                2,
                1,
                Arc::new(move |_, _| {
                    let count = counted.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    if count < 2 {
                        // Independent watchdog ensures a failed test cannot retain test workers forever.
                        released
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .unwrap();
                    }
                    Ok(vec![public()])
                }),
            )
            .unwrap(),
        );
        let mut callers = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            callers.push(std::thread::spawn(move || {
                pool.resolve(
                    "storage.example.com",
                    443,
                    Instant::now() + Duration::from_millis(500),
                )
            }));
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        for caller in callers {
            assert_eq!(caller.join().unwrap(), Err(Error::Deadline));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            pool.resolve(
                "queued.example.com",
                443,
                Instant::now() + Duration::from_millis(20)
            ),
            Err(Error::Deadline)
        );
        assert_eq!(
            pool.resolve(
                "busy.example.com",
                443,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error::Busy)
        );
        release.send(()).unwrap();
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match pool.resolve("fresh.example.com", 443, deadline) {
                Err(Error::Busy) if Instant::now() < deadline => std::thread::yield_now(),
                answer => {
                    assert_eq!(answer.unwrap(), vec![public()]);
                    break;
                }
            }
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "expired queued lookup must never reach the native resolver"
        );
    }

    #[test]
    fn expired_and_oversized_requests_never_enter_the_resolver() {
        let pool = Pool::new(
            1,
            1,
            Arc::new(|_, _| panic!("invalid DNS request reached resolver")),
        )
        .unwrap();
        assert_eq!(
            pool.resolve("storage.example.com", 443, Instant::now()),
            Err(Error::Deadline)
        );
        assert_eq!(
            pool.resolve(
                &"a".repeat(HOST_BYTES + 1),
                443,
                Instant::now() + Duration::from_secs(1)
            ),
            Err(Error::Invalid)
        );
    }
}

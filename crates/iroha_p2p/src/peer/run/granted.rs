//! Mandatory grant-framed peer lifetime, after the authenticated identity handshake.
use super::super::receive_credit::{negotiation, stream::CreditStream};
use super::*;
use crate::TransportAdmissionClass as Class;

/// Poll ready semantic FIFOs in rotating order, without removing a post whose
/// class cannot yet enter the writer. Every removed post transfers its owner.
pub(super) async fn next_post<T>(
    receivers: &mut [post_channel::Receiver<RetainedPost<T>>; Class::COUNT],
    eligible: [bool; Class::COUNT],
    cursor: &mut usize,
) -> Option<RetainedPost<T>> {
    std::future::poll_fn(|cx| {
        let mut open = false;
        for offset in 0..Class::SCHEDULE.len() {
            let rank = (*cursor + offset) % Class::SCHEDULE.len();
            let i = Class::SCHEDULE[rank].index();
            open |= !receivers[i].is_closed() || !receivers[i].is_empty();
            if !eligible[i] {
                continue;
            }
            if let std::task::Poll::Ready(Some(post)) = receivers[i].poll_recv(cx) {
                *cursor = (rank + 1) % Class::SCHEDULE.len();
                return std::task::Poll::Ready(Some(post));
            }
        }
        if open {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(None)
        }
    })
    .await
}

async fn dispatch<T: Pload + ClassifyTopic>(
    mut receiver: mpsc::UnboundedReceiver<PendingInbound<T>>,
    senders: PeerMessageSenders<T>,
    class: Class,
) {
    while let Some(mut pending) = receiver.recv().await {
        // Only a real, authenticated, exactly classified grant can enter this
        // path. No deferred acquisition or caller-priority fallback exists.
        if pending.message.granted_admission_class() != Some(class)
            || pending.message.payload.admission_class() != class
        {
            iroha_logger::error!(?class, "Granted semantic dispatch ownership mismatch");
            break;
        }
        let admission = senders
            .transfer_before_send(&mut pending.message, pending.topic, pending.priority, false)
            .await;
        match admission {
            InboundDispatchAdmission::Admitted => {}
            InboundDispatchAdmission::OverTopicCap { cap } => {
                iroha_logger::error!(
                    ?class,
                    cap,
                    "Granted semantic dispatch exceeded its topic cap"
                );
                break;
            }
            InboundDispatchAdmission::ByteBudgetFull => {
                iroha_logger::error!(
                    ?class,
                    "Granted semantic dispatch violated admitted geometry"
                );
                break;
            }
        }
        let sender = match class {
            Class::Safety => &senders.safety,
            Class::Lane => &senders.high,
            Class::Payload => &senders.payload,
            Class::BlockSync => &senders.block_sync,
            Class::Control => &senders.control,
            Class::Low => &senders.low,
        };
        if sender.send(pending.message).await.is_err() {
            break;
        }
    }
}

pub(super) async fn run<T: Pload + ClassifyTopic, E: Enc, P: Entrypoint<E>>(
    args: RunPeerArgs<T, P>,
) {
    let RunPeerArgs {
        peer,
        service_message_sender,
        idle_timeout,
        authentication_deadline,
        inbound_auth_completion,
        post_capacity,
        outbound_frame_queue_limits,
        outbound_post_byte_budgets,
        inbound_frame_byte_budgets,
        max_frame_bytes,
        quic_datagrams_enabled,
        quic_datagram_max_payload_bytes,
    } = args;
    let conn_id = peer.connection_id();
    let mut termination_guard =
        PeerTaskTerminationGuard::new(service_message_sender.clone(), conn_id);
    async {
            // Try to do handshake process
            let hs_start = Instant::now();
            let handshake_result = authentication_deadline
                .run(None, peer.handshake())
                .await;
            let ready_peer = match handshake_result {
                Ok(Ok(ready)) => {
                    let ms = u64::try_from(hs_start.elapsed().as_millis()).unwrap_or(u64::MAX);
                    observe_handshake_ms(ms);
                    ready
                }
                Ok(Err(error)) => {
                    iroha_logger::warn!(?error, "Failure during handshake.");
                    HANDSHAKE_FAILURES.fetch_add(1, Ordering::Relaxed);
                    match error {
                        Error::HandshakeBadPreface => { HSE_PREFACE.fetch_add(1, Ordering::Relaxed); },
                        Error::Keys(_)
                        | Error::HandshakePeerMismatch { .. }
                        | Error::HandshakeNodeAlgorithmMismatch { .. }
                        | Error::HandshakeSoranetDelegation(_) => {
                            HSE_VERIFY.fetch_add(1, Ordering::Relaxed);
                        },
                        Error::SymmetricEncryption(_) => { HSE_DECRYPT.fetch_add(1, Ordering::Relaxed); },
                        Error::NoritoCodec(_) => { HSE_CODEC.fetch_add(1, Ordering::Relaxed); },
                        Error::Io(_) => { HSE_IO.fetch_add(1, Ordering::Relaxed); },
                        _ => { HSE_OTHER.fetch_add(1, Ordering::Relaxed); },
                    }
                    return;
                },
                Err(_) => {
                    iroha_logger::warn!(?authentication_deadline, "Peer exhausted its authentication deadline");
                    HANDSHAKE_FAILURES.fetch_add(1, Ordering::Relaxed);
                    HSE_TIMEOUT.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
        let (termination_sender, mut termination_receiver) = watch::channel(false);
        let (reader_sender, reader_receiver) = oneshot::channel();
        let candidate = Authenticated {
            peer: ready_peer.peer.clone(), connection_id: ready_peer.connection.id,
            session: ready_peer.cryptographer.session_binding,
            relay_role: ready_peer.relay_role,
            cancel: termination_sender.clone(), reply: reader_sender,
        };
        termination_guard.set_peer(ready_peer.peer.clone());
        let permission = authentication_deadline.run(None, async {
            tokio::select! {
                biased;
                () = super::super::tenure::cancelled(&mut termination_receiver) => None,
                permission = async {
                    service_message_sender.send(ServiceMessage::Authenticated(candidate)).await.ok()?;
                    reader_receiver.await.ok()
                } => permission,
            }
        }).await;
        let Ok(Some(permit)) = permission else { return; };
        let termination_guard = &mut termination_guard;
        // The boxed operation owns Ready (including both I/O halves) before it
        // can bind a source. Its field drops before the exclusive reader permit,
        // including cancellation before the operation's first poll.
        permit.run(async move {
        if *termination_receiver.borrow_and_update() { return; }
        let Ready {
            network_id, local_peer_id, peer: peer_id,
            connection: Connection { read, write, read_low, write_low, quic, transport_binding,
                #[cfg(feature="quic")] quic_datagrams, id: connection_id, .. },
            cryptographer, relay_role, scion_supported, trust_gossip,
        } = ready_peer;
        // QUIC is rejected by shipping configuration before transport creation.
        // An unexpected alternate stream cannot bypass mandatory credit records.
        #[cfg(feature="quic")]
        let has_datagrams = quic_datagrams.is_some();
        #[cfg(not(feature="quic"))]
        let has_datagrams = false;
        if read_low.is_some() || write_low.is_some() || quic.is_some() || has_datagrams || quic_datagrams_enabled {
            iroha_logger::error!("Unsupported transport bypassed mandatory credit admission"); return;
        }
        let _ = quic_datagram_max_payload_bytes;
        let Some(transport_binding) = transport_binding else {
            iroha_logger::error!("Authenticated credit transport lacks channel binding"); return;
        };
        let pool = match inbound_frame_byte_budgets.admitted_receive_credit_pool() {
            Ok(pool) => pool, Err(error) => { iroha_logger::error!(?error, "Missing admitted credit geometry"); return; }
        };
        let source = match pool.bind(peer_id.id()) {
            Ok(source) => source, Err(error) => { iroha_logger::warn!(?error, "PeerId credit tenure is still owned or geometry is exhausted"); return; }
        };
        let disambiguator = cryptographer.disambiguator;
        // Both halves are owned by exchange. Timeout/cancellation closes them
        // before the source ledger/control lease is reclaimed. The original
        // authentication deadline covers identity AND geometry, without reset.
        let geometry = authentication_deadline.run(None, negotiation::exchange(
            negotiation::OwnedTransport { read, write, source }, &cryptographer,
            &network_id, &local_peer_id, peer_id.id(), transport_binding,
        ));
        let negotiated = tokio::select! {
            biased;
            () = super::super::tenure::cancelled(&mut termination_receiver) => { return; }
            result = geometry => match result {
                Ok(Ok(negotiated)) => negotiated,
                Ok(Err(error)) => { iroha_logger::warn!(?error, "Mandatory receive-credit geometry exchange failed"); HANDSHAKE_FAILURES.fetch_add(1, Ordering::Relaxed); return; }
                Err(error) => { iroha_logger::warn!(?error, "Mandatory receive-credit geometry deadline expired"); HANDSHAKE_FAILURES.fetch_add(1, Ordering::Relaxed); return; }
            }
        };
        if let Some(completion) = inbound_auth_completion
            && !completion.complete() { iroha_logger::warn!("Inbound credit authentication ownership expired"); return; }
        let post_source=match outbound_post_byte_budgets.semantic().and_then(|pool|pool.bind(peer_id.id())) {
            Ok(source)=>source,Err(error)=>{iroha_logger::error!(?error,"missing admitted semantic post source");return;}
        };
        let (senders, mut post_receivers) = handles::class_channels(post_capacity);

        let (peer_message_sender, peer_message_receiver) = oneshot::channel();
        let delivery_drain = Arc::new(InboundDeliveryDrain::new());
        termination_guard.set_delivery_drain(Arc::clone(&delivery_drain));
        let ready_peer_handle = handles::PeerHandle {
            senders, termination_sender, post_admission:post_admission::Admission::Granted(post_source),
        };
        let handoff = async {
            service_message_sender.send(ServiceMessage::Connected(Connected {
            connection_id, peer: peer_id.clone(), ready_peer_handle, peer_message_sender,
            delivery_drain: Arc::clone(&delivery_drain), disambiguator, relay_role, scion_supported, trust_gossip,
        })).await.ok()?;
            peer_message_receiver.await.ok()
        };
        let handoff = authentication_deadline.run(None, handoff);
        let peer_message_senders = tokio::select! {
            biased;
            () = super::super::tenure::cancelled(&mut termination_receiver) => { return; }
            result = handoff => match result {
                Ok(Some(senders)) => senders,
                _ => return,
            }
        };
        let negotiation::Negotiated { transport, binding, outbound_maximum } = negotiated;
        let mut stream = match CreditStream::new(
        transport,
        binding,
        cryptographer,
        peer_id,
        connection_id,
        super::super::receive_credit::stream::CreditStreamConfig { caps: peer_message_senders.topic_frame_caps, maximum: outbound_maximum, limits: outbound_frame_queue_limits, idle_timeout },
    ) {
            Ok(stream) => stream, Err(error) => { iroha_logger::error!(?error, "Admitted credit writer geometry cannot be installed"); return; }
        };
        let _ = max_frame_bytes; // Geometry was capped before any listener/dialer started.
        let mut producers = Vec::with_capacity(Class::COUNT);
        let mut workers = Vec::with_capacity(Class::COUNT);
        for class in Class::ALL {
            let (tx, rx) = mpsc::unbounded_channel();
            // Queue count and every resident byte are pre-reserved by grants;
            // no allocation-sized object enters an uncharged unbounded queue.
            producers.push(tx);
            workers.push(tokio::spawn(dispatch(rx, peer_message_senders.clone(), class)));
        }
        termination_guard.set_dispatch_workers(producers.clone(), InboundDispatchWorkers(workers));
        let ping_period = (idle_timeout / 2).max(Duration::from_nanos(1));
        let mut ping = tokio::time::interval_at(Instant::now() + ping_period, ping_period);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        let mut cursor = 0;
        let mut post_burst = 0;
        let mut posts_open = true;
        let mut termination_open = true;
        loop {
            if *termination_receiver.borrow_and_update() { break; }
            let eligible = Class::ALL.map(|class| stream.can_enqueue(class));
            let authenticated_before = stream.authenticated_records();
            tokio::select! {
                biased;
                changed = termination_receiver.changed(), if termination_open => {
                    if changed.is_err() { termination_open = false; }
                    else if *termination_receiver.borrow_and_update() { break; }
                }
                () = &mut idle => { iroha_logger::debug!("Authenticated credit peer idle timeout"); break; }
                _ = ping.tick() => { if stream.request_ping().is_err() { break; } }
                post = next_post(&mut post_receivers, eligible, &mut cursor), if posts_open && post_burst < Class::COUNT => {
                    match post {
                        Some(post) => {
                            post_burst += 1;
                            if let Err((error, retained)) = stream.enqueue(post) {
                                // Dropping the exact accepted post closes its flush ACK;
                                // the upstream retained sender owns retry, never a fake ACK.
                                drop(retained);
                                iroha_logger::warn!(?error, "Admitted post failed canonical credit encoding"); break;
                            }
                        }
                        None => posts_open = false,
                    }
                }
                result = stream.step() => {
                    post_burst = 0;
                    match result {
                        Ok(message) => {
                            if stream.authenticated_records() != authenticated_before { idle.as_mut().reset(Instant::now() + idle_timeout); }
                            if let Some(message) = message {
                                let class = message.payload.admission_class();
                                let topic = message.payload.topic();
                                let priority = message.payload.priority();
                                if producers[class.index()].send(PendingInbound { message, topic, priority }).is_err() { break; }
                            }
                        }
                        Err(error) => { iroha_logger::warn!(?error, "Mandatory credit record stream failed"); break; }
                    }
                }

            }
        }
        // Actual stream drops I/O before ledger. Delivered old-tenure messages
        // remain with workers and final consumers, sharing the strong PeerId owner.
        drop(stream);
        drop(post_receivers);
        drop(producers);
        }).await;
    }.await;
    termination_guard.finish().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::admission_class_tests::AdmissionFixture as Fixture;
    fn post(payload: Fixture) -> RetainedPost<Fixture> {
        let bytes = SharedByteBudget::new(4096, 0).unwrap();
        RetainedPost::new(
            payload,
            OutboundPostOwnership::new(bytes.try_reserve(2048, false).unwrap(), None),
        )
    }
    #[tokio::test]
    async fn semantic_post_poll_skips_ungranted_bulk_and_preserves_fifo_and_eventual_service() {
        let (senders, mut receivers) = handles::class_channels(2);
        for value in Fixture::all() {
            assert!(
                senders.classes[value.admission_class().index()]
                    .try_send(post(value))
                    .is_ok(),
                "bounded fixture post"
            );
        }
        assert!(
            senders.classes[Class::Payload.index()]
                .try_send(post(Fixture::Payload(19)))
                .is_ok(),
            "second bounded fixture post"
        );
        let mut eligible = [true; Class::COUNT];
        eligible[Class::Payload.index()] = false;
        let mut cursor = Class::Payload.index();
        let mut observed = Vec::new();
        for _ in 0..Class::COUNT - 1 {
            let value = next_post(&mut receivers, eligible, &mut cursor)
                .await
                .unwrap();
            observed.push(value.message.as_ref().unwrap().admission_class());
        }
        let mut expected: Vec<_> = Class::ALL
            .into_iter()
            .filter(|class| *class != Class::Payload)
            .collect();
        observed.sort();
        expected.sort();
        assert_eq!(observed, expected);
        assert_eq!(
            receivers[Class::Payload.index()].len(),
            2,
            "ungranted FIFO was never popped"
        );
        eligible[Class::Payload.index()] = true;
        for ordinal in [3, 19] {
            let value = next_post(&mut receivers, eligible, &mut cursor)
                .await
                .unwrap();
            assert!(
                matches!(value.message.as_ref(), Some(Fixture::Payload(actual)) if *actual == ordinal)
            );
        }
        drop(senders);
        assert!(
            next_post(&mut receivers, eligible, &mut cursor)
                .await
                .is_none()
        );
    }
}

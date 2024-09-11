use std::time::Duration;

use iroha_logger::{
    debug, info,
    layer::{EventInspectorTrait, EventSubscriber, LevelFilter},
    trace,
};
use tokio::{sync::mpsc, time};
use tracing::{Event, Level, Subscriber};

struct SenderFilter<S> {
    sender: mpsc::UnboundedSender<()>,
    sub: S,
}

impl<S: Subscriber> SenderFilter<S> {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(sub: S) -> (impl Subscriber, mpsc::UnboundedReceiver<()>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (EventSubscriber(Self { sender, sub }), receiver)
    }
}

impl<S: Subscriber> EventInspectorTrait for SenderFilter<S> {
    type Subscriber = S;

    fn inner_subscriber(&self) -> &Self::Subscriber {
        &self.sub
    }

    fn event(&self, event: &Event<'_>) {
        self.sender.send(()).unwrap();
        self.sub.event(event)
    }
}

#[tokio::test]
async fn test() {
    let (sub, mut rcv) = SenderFilter::new(
        tracing_subscriber::fmt()
            .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
            .finish(),
    );
    let sub = LevelFilter::new(Level::DEBUG, sub);
    tracing::subscriber::set_global_default(sub).unwrap();

    trace!(a = 2, c = true);
    debug!(a = 2, c = true);
    info!(a = 2, c = true);

    time::timeout(Duration::from_millis(10), rcv.recv())
        .await
        .unwrap()
        .unwrap();
    time::timeout(Duration::from_millis(10), rcv.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(time::timeout(Duration::from_millis(10), rcv.recv())
        .await
        .is_err());
}

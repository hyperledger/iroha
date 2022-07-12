use iroha_actor::{broker::*, prelude::*};

struct Alice(Broker);

struct Bob(Broker);

struct Carol(Broker);

#[derive(Clone, Debug, Message)]
#[message(result = "()")]
struct MsgXA;

#[derive(Clone, Debug, Message)]
#[message(result = "()")]
struct MsgAB;

#[derive(Clone, Debug, Message)]
#[message(result = "()")]
struct MsgAC;

#[derive(Clone, Debug, Message)]
#[message(result = "()")]
struct MsgBC;

#[async_trait::async_trait]
impl Actor for Alice {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.0.subscribe::<MsgXA, _>(ctx);
    }
}

#[async_trait::async_trait]
impl Actor for Bob {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.0.subscribe::<MsgAB, _>(ctx);
    }
}

#[async_trait::async_trait]
impl Actor for Carol {
    async fn on_start(&mut self, ctx: &mut Context<Self>) {
        self.0.subscribe::<MsgAC, _>(ctx);
        self.0.subscribe::<MsgBC, _>(ctx);
    }
}

#[async_trait::async_trait]
impl Handler<MsgXA> for Alice {
    type Result = ();
    async fn handle(&mut self, msg: MsgXA) {
        println!("{:?}", msg);
        self.0.issue_send(MsgAB).await;
        self.0.issue_send(MsgAC).await;
    }
}

#[async_trait::async_trait]
impl Handler<MsgAB> for Bob {
    type Result = ();
    async fn handle(&mut self, msg: MsgAB) {
        println!("{:?}", msg);
        self.0.issue_send(MsgBC).await;
    }
}

#[async_trait::async_trait]
impl Handler<MsgAC> for Carol {
    type Result = ();
    async fn handle(&mut self, msg: MsgAC) {
        println!("{:?}", msg);
    }
}

#[async_trait::async_trait]
impl Handler<MsgBC> for Carol {
    type Result = ();
    async fn handle(&mut self, msg: MsgBC) {
        println!("{:?}", msg);
    }
}

#[tokio::main]
async fn main() {
    let broker = Broker::new();
    Alice(broker.clone()).start().await;
    Bob(broker.clone()).start().await;
    Carol(broker.clone()).start().await;
    broker.issue_send(MsgXA).await;
    // Expected:
    // MsgXA, MsgAB, MsgAC, and MsgBC appear once each （may be in no particular order)
}

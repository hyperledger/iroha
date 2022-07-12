use iroha_actor::{broker::*, prelude::*};

#[subscribe(MsgAA)]
#[publish(MsgAA, MsgAB, MsgAC)]
struct Alice;

#[subscribe(MsgAB)]
#[publish(MsgBC)]
struct Bob;

#[subscribe(MsgAC, MsgBC)]
struct Carol;

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

impl Subscribe<MsgAA> for Alice {
    fn handle(&mut self, msg: MsgAA) {
        println!("{:?}", msg);
        self.publish(MsgAB);
        self.publish(MsgAC);
    }
}

impl Subscribe<MsgAB> for Bob {
    fn handle(&mut self, msg: MsgAB) {
        println!("{:?}", msg);
        self.publish(MsgBC);
    }
}

impl Subscribe<MsgAC> for Carol {
    fn handle(&mut self, msg: MsgAC) {
        println!("{:?}", msg);
    }
}

impl Subscribe<MsgBC> for Carol {
    fn handle(&mut self, msg: MsgBC) {
        println!("{:?}", msg);
    }
}

#[tokio::main]
async fn main() {
    // Establish all the possible channels at the components initialization
    let (alice, bob, carol) = new_with_channels!(Alice, Bob, Carol);

    alice.start().await;
    bob.start().await;
    carol.start().await;

    alice.publish(MsgAA);
    // Expected:
    // MsgAA, MsgAB, MsgAC, and MsgBC appear once each （may be in no particular order)
}

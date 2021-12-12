//! Binary to print all types to json string

#![allow(clippy::print_stdout)]

use std::collections::BTreeMap;

use iroha_core::block::stream::prelude::*;
use iroha_schema::prelude::*;

macro_rules! to_json {
    ($($t:ty),* $(,)?) => {{
        let mut out = BTreeMap::new();
        $(<$t as IntoSchema>::schema(&mut out);)*
        serde_json::to_string_pretty(&out).unwrap()
    }};
}

fn main() {
    use iroha_core::genesis::RawGenesisBlock;
    use iroha_data_model::{
        expression::*,
        isi::{If, *},
        prelude::*,
    };

    let json = to_json! {
        // $ rg '^pub (struct|enum)' | rg -v '(<|Builder|LengthLimits|QueryRequest)' | cut -d' ' -f3 | sed -e 's/[(].*//' -e 's/$/,/' | sort
        Add,
        And,
        BlockPublisherMessage,
        BlockSubscriberMessage,
        BurnBox,
        Contains,
        ContainsAll,
        ContainsAny,
        ContextValue,
        Divide,
        Equal,
        Event,
        EventFilter,
        EventPublisherMessage,
        EventSubscriberMessage,
        Expression,
        FailBox,
        GrantBox,
        Greater,
        IdBox,
        IdentifiableBox,
        If,
        If,
        Instruction,
        Less,
        MintBox,
        Mod,
        Multiply,
        Not,
        Or,
        Pair,
        Parameter,
        Payload,
        QueryBox,
        QueryResult,
        RaiseTo,
        RegisterBox,
        RemoveKeyValueBox,
        SequenceBox,
        SetBox,
        SetKeyValueBox,
        SignedQueryRequest,
        Subtract,
        TransferBox,
        UnregisterBox,
        Value,
        Where,

        // All versioned
        VersionedBlockPublisherMessage,
        VersionedBlockSubscriberMessage,
        VersionedEventPublisherMessage,
        VersionedEventSubscriberMessage,
        VersionedQueryResult,
        VersionedSignedQueryRequest,
        VersionedTransaction,

        RawGenesisBlock
    };

    println!("{}", json)
}

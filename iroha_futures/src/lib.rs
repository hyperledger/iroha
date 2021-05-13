//! Crate with various iroha futures

use std::{
    convert::TryFrom,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

pub use futures_derive::*;
use iroha_logger::telemetry::{Telemetry, TelemetryFields};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Future which sends info with telemetry about number and length of polls
#[derive(Debug, Clone, Copy)]
pub struct TelemetryFuture<F> {
    future: F,
    id: u64,
    name: &'static str,
}

impl<F> TelemetryFuture<F> {
    /// Constructor for future
    pub fn new(future: F, name: &'static str) -> Self {
        let id = rand::random();
        Self { future, name, id }
    }
}

/// Telemetry info for future polling
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FuturePollTelemetry {
    /// Future id
    pub id: u64,
    /// Future name
    pub name: String,
    /// Duration of poll
    pub duration: Duration,
}

/// Error which happends during conversion from telemetry
#[derive(Debug, Clone, Copy)]
pub struct FromTelemetryError;

impl TryFrom<&Telemetry> for FuturePollTelemetry {
    type Error = FromTelemetryError;

    #[allow(clippy::unwrap_in_result, clippy::unwrap_used)]
    fn try_from(Telemetry { target, fields }: &Telemetry) -> Result<Self, FromTelemetryError> {
        if target != &"iroha_futures" && fields.len() != 3 {
            return Err(FromTelemetryError);
        }

        let TelemetryFields(fields) = fields;
        let (mut id, mut name, mut duration) = (None, None, None);

        for field in fields {
            match field {
                ("id", Value::Number(id_value)) if id.is_none() => {
                    id = Some(id_value.as_u64().unwrap())
                }
                ("name", Value::String(name_value)) if name.is_none() => name = Some(name_value),
                ("duration", Value::Number(duration_value)) if duration.is_none() => {
                    duration = Some(Duration::from_nanos(duration_value.as_u64().unwrap()))
                }
                _ => return Err(FromTelemetryError),
            }
        }

        Ok(Self {
            id: id.unwrap(),
            name: name.unwrap().clone(),
            duration: duration.unwrap(),
        })
    }
}

impl TryFrom<Telemetry> for FuturePollTelemetry {
    type Error = FromTelemetryError;

    #[allow(clippy::unwrap_in_result, clippy::unwrap_used)]
    fn try_from(Telemetry { target, fields }: Telemetry) -> Result<Self, FromTelemetryError> {
        if target != "iroha_futures" && fields.len() != 3 {
            return Err(FromTelemetryError);
        }

        let TelemetryFields(fields) = fields;
        let (mut id, mut name, mut duration) = (None, None, None);

        for field in fields {
            match field {
                ("id", Value::Number(id_value)) if id.is_none() => {
                    id = Some(id_value.as_u64().unwrap())
                }
                ("name", Value::String(name_value)) if name.is_none() => name = Some(name_value),
                ("duration", Value::Number(duration_value)) if duration.is_none() => {
                    duration = Some(Duration::from_nanos(duration_value.as_u64().unwrap()))
                }
                _ => return Err(FromTelemetryError),
            }
        }

        Ok(Self {
            id: id.unwrap(),
            name: name.unwrap(),
            duration: duration.unwrap(),
        })
    }
}

impl<F: Future> Future for TelemetryFuture<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let name = self.name;
        let id = self.id;
        let now = Instant::now();

        // SAFETY: This is safe because `future` is a field of pinned structure and therefore is also pinned
        #[allow(unsafe_code)]
        let future = unsafe { self.map_unchecked_mut(|telemetry| &mut telemetry.future) };
        let result = future.poll(cx);

        // 100 seconds in nanos is less than 2 ** 37. It would be more than enough for us
        #[allow(clippy::cast_possible_truncation)]
        let duration = now.elapsed().as_nanos() as u64;
        iroha_logger::telemetry!(id, name, duration);

        result
    }
}

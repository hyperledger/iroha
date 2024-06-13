//! Custom `serde` impls. Keep them here to reduce clutter.

impl serde::Serialize for super::EchoOk {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_str(super::ECHO_OK)
    }
}

impl<const VALUE: bool> serde::Serialize for super::Bool<VALUE> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_bool(VALUE)
    }
}

impl serde::Serialize for super::ImageBuilderRef {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_str(super::IMAGE_BUILDER)
    }
}

impl serde::Serialize for super::SignAndSubmitGenesis {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_str(super::SIGN_AND_SUBMIT_GENESIS)
    }
}

impl serde::Serialize for super::PortMapping {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_str(&format!("{}:{}", self.0, self.1))
    }
}

impl serde::Serialize for super::PathMapping<'_> {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_str(&format!("{}:{}", self.0 .0.as_ref().display(), self.1 .0))
    }
}

impl serde::Serialize for super::Healthcheck {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        let mut ser = ser.serialize_map(Some(5))?;
        ser.serialize_entry(
            "test",
            &format!(
                "test $(curl -s http://127.0.0.1:{}/status/blocks) -gt 0",
                self.port
            ),
        )?;
        ser.serialize_entry("interval", super::HEALTH_CHECK_INTERVAL)?;
        ser.serialize_entry("timeout", super::HEALTH_CHECK_TIMEOUT)?;
        ser.serialize_entry("retries", &super::HEALTH_CHECK_RETRIES)?;
        ser.serialize_entry("start_period", super::HEALTH_CHECK_START_PERIOD)?;
        ser.end()
    }
}

impl serde::Serialize for super::IrohadRef {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_str(&format!("{}{}", crate::peer::SERVICE_NAME, self.0))
    }
}

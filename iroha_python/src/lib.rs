// Allow panic because of bad and unsafe pyo3
#![allow(clippy::panic)]

use std::ops::{Deref, DerefMut};

use iroha_client::{client, config};
use iroha_data_model::prelude::*;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

macro_rules! wrap_class {
    (
        $(
            $ty:ident {
                $field:ident : $outer_ty:ty
            } : $( $derive:ident $(+)? )*
        ),*
        $(,)?
    ) => {$(
        #[pyclass]
        #[derive($($derive,)*)]
        pub struct $ty {
            $field: $outer_ty,
        }

        impl Deref for $ty {
            type Target = $outer_ty;
            fn deref(&self) -> &Self::Target {
                &self.$field
            }
        }

        impl DerefMut for $ty {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.$field
            }
        }

        impl From<$outer_ty> for $ty {
            fn from(outer: $outer_ty) -> Self {
                Self {
                    $field: outer,
                }
            }
        }

        impl From<$ty> for $outer_ty {
            fn from(from: $ty) -> Self {
                from.$field
            }
        }

        #[pymethods]
        impl $ty {
            fn __str__(&self) -> String {
                format!("{:#?}", self)
            }
        }
    )*
        fn register_wrapped_classes(m: &PyModule) -> PyResult<()> {
            $(m.add_class::<$ty>()?;)*
            Ok(())
        }
    };
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Dict<T>(T);

impl<T> Deref for Dict<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Dict<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> Dict<T> {
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<'source, T: serde::de::DeserializeOwned> FromPyObject<'source> for Dict<T> {
    fn extract(obj: &'source PyAny) -> PyResult<Self> {
        pythonize::depythonize(obj).map_err(to_py_err).map(Self)
    }
}

impl<'source, T: serde::Serialize> IntoPy<PyObject> for Dict<T> {
    fn into_py(self, py: Python) -> PyObject {
        #[allow(clippy::clippy::expect_used)]
        pythonize::pythonize(py, &self.into_inner()).expect("Lets hope serde won't complain :(")
    }
}

fn to_py_err(err: impl Into<iroha_error::Error>) -> PyErr {
    PyException::new_err(err.into().report().to_string())
}

#[pymethods]
impl KeyPair {
    /// Generates new key
    /// # Errors
    #[new]
    pub fn generate() -> PyResult<Self> {
        let keys = iroha_crypto::KeyPair::generate().map_err(to_py_err)?;
        Ok(Self { keys })
    }

    #[getter]
    pub fn public(&self) -> PublicKey {
        self.public_key.clone().into()
    }

    #[getter]
    pub fn private(&self) -> PrivateKey {
        self.private_key.clone().into()
    }
}

#[pymethods]
impl AccountId {
    #[new]
    fn new(name: String, domain: String) -> Self {
        let domain_name = domain;
        iroha_data_model::prelude::AccountId { name, domain_name }.into()
    }
}

#[pymethods]
impl Configuration {
    #[new]
    #[args(keys = "None")]
    fn new(id: AccountId, peer_url: String, keys: Option<KeyPair>) -> PyResult<Self> {
        let keys = keys.map_or_else(KeyPair::generate, Ok)?;
        let iroha_crypto::KeyPair {
            public_key,
            private_key,
        } = keys.into();

        #[allow(clippy::default_trait_access)]
        Ok(config::Configuration {
            account_id: id.into(),
            torii_api_url: peer_url,
            public_key,
            private_key,

            max_instruction_number: 2_usize.pow(12),
            transaction_status_timeout_ms: 3000,
            transaction_time_to_live_ms: 100_000,

            // Allow as we don't have access to it
            // Should we remove this lint or just change api of Configuration?
            logger_configuration: Default::default(),
        }
        .into())
    }

    #[new]
    fn from_file(file: String) -> PyResult<Self> {
        iroha_client::config::Configuration::from_path(file)
            .map_err(to_py_err)
            .map(Into::into)
    }
}

#[pymethods]
impl Client {
    #[new]
    pub fn new(cfg: &Configuration) -> Self {
        client::Client::new(cfg).into()
    }

    /// Queries peer
    /// # Errors
    /// Can fail if there is no access to peer
    pub fn request(&mut self, query: Dict<QueryBox>) -> PyResult<Dict<Value>> {
        self.deref_mut()
            .request(query.into_inner())
            .map_err(to_py_err)
            .map(Dict)
    }

    /// Sends transaction to peer
    /// # Errors
    /// Can fail if there is no access to peer
    pub fn submit_all_with_metadata(
        &mut self,
        isi: Vec<Dict<Instruction>>,
        metadata: Dict<UnlimitedMetadata>,
    ) -> PyResult<Hash> {
        let isi = isi.into_iter().map(Dict::into_inner).collect();
        self.deref_mut()
            .submit_all_with_metadata(isi, metadata.into_inner())
            .map_err(to_py_err)
            .map(Into::into)
    }

    /// Sends transaction to peer and waits till its finalization
    /// # Errors
    /// Can fail if there is no access to peer
    pub fn submit_all_blocking_with_metadata(
        &mut self,
        isi: Vec<Dict<Instruction>>,
        metadata: Dict<UnlimitedMetadata>,
    ) -> PyResult<Hash> {
        let isi = isi.into_iter().map(Dict::into_inner).collect();
        self.deref_mut()
            .submit_all_blocking_with_metadata(isi, metadata.into_inner())
            .map_err(to_py_err)
            .map(Into::into)
    }
}

#[rustfmt::skip]
wrap_class!(
    PublicKey     { key:  iroha_crypto::PublicKey                 }: Debug + Clone,
    PrivateKey    { key:  iroha_crypto::PrivateKey                }: Debug + Clone,
    KeyPair       { keys: iroha_crypto::KeyPair                   }: Debug + Clone,
    Hash          { hash: iroha_crypto::Hash                      }: Debug + Clone + Copy,
    Configuration { cfg:  config::Configuration                   }: Debug + Clone,
    Client        { cl:   client::Client                          }: Debug + Clone,
    AccountId     { id:   iroha_data_model::prelude::AccountId    }: Debug + Clone,
);

/// A Python module implemented in Rust.
#[pymodule]
pub fn iroha2(_: Python, m: &PyModule) -> PyResult<()> {
    register_wrapped_classes(m)?;
    Ok(())
}

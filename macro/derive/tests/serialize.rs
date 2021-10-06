#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

    use std::{collections::BTreeMap, convert::TryFrom};

    use iroha_derive::Io;
    use parity_scale_codec::{Decode, Encode};

    #[derive(Io, Encode, Decode, PartialEq, Debug, Clone)]
    struct SampleContract {
        boolean_field: bool,
        string_field: String,
        vec_field: Vec<String>,
        map_field: BTreeMap<String, String>,
    }

    impl SampleContract {
        fn new() -> Self {
            SampleContract {
                boolean_field: true,
                string_field: "String".to_owned(),
                vec_field: vec!["String_In_Vec".to_owned()],
                map_field: BTreeMap::new(),
            }
        }
    }

    #[test]
    fn reference_convert_to_and_from_bytes_vec() {
        let sample_contract = SampleContract::new();
        let sample_contract_ref = &sample_contract;
        let vector_from_ref: Vec<u8> = sample_contract_ref.into();
        let result_from_ref =
            SampleContract::try_from(vector_from_ref).expect("Failed to try from vector.");
        assert_eq!(sample_contract, result_from_ref);
    }

    #[test]
    fn clone_convert_to_and_from_bytes_vec() {
        let sample_contract = SampleContract::new();
        let sample_contract_clone = sample_contract.clone();
        let vector_from_clone: Vec<u8> = sample_contract_clone.into();
        let result_from_clone =
            SampleContract::try_from(vector_from_clone).expect("Failed to try from vector.");
        assert_eq!(sample_contract, result_from_clone);
    }
}

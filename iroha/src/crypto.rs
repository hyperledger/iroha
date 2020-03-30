pub type Hash = [u8; 32];

#[test]
fn blake2_32b() {
    use hex_literal::hex;
    use ursa::blake2::{
        digest::{Input, VariableOutput},
        VarBlake2b,
    };

    let mut hasher = VarBlake2b::new(32).unwrap();

    hasher.input(hex!("6920616d2064617461"));
    hasher.variable_result(|res| {
        assert_eq!(
            res[..],
            hex!("ba67336efd6a3df3a70eeb757860763036785c182ff4cf587541a0068d09f5b2")[..]
        );
    })
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Signature {}

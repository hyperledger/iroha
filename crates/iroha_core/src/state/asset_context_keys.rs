//! One exact spelling for UID/FI observation keys and fallible admitted ownership.
//! All formatting buffers are fixed stack storage; account text is canonical I105
//! produced by Native under its caller's existing codec admission scope.
use super::*;
use std::io::Write as _;

type Hex = [u8; 64];
fn hex(bytes: &[u8; 32]) -> Hex {
    let mut result = [0; 64];
    hex::encode_to_slice(bytes, &mut result).expect("exact fixed hash buffer");
    result
}
fn definition(definition: &AssetDefinitionId) -> Result<Hex, norito::Error> {
    let mut text = std::io::Cursor::new([0_u8; 64]);
    write!(&mut text, "{definition}").map_err(|_| norito::Error::LengthMismatch)?;
    Ok(hex(
        Hash::new(&text.get_ref()[..text.position() as usize]).as_ref()
    ))
}
fn account(text: &str) -> Hex {
    hex(Hash::new(text.as_bytes()).as_ref())
}
fn key_text(root: &str, components: &[Hex]) -> Result<std::io::Cursor<[u8; 384]>, norito::Error> {
    let mut text = std::io::Cursor::new([0_u8; 384]);
    text.write_all(root.as_bytes())
        .map_err(|_| norito::Error::LengthMismatch)?;
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            text.write_all(b"/")
                .map_err(|_| norito::Error::LengthMismatch)?;
        }
        text.write_all(component)
            .map_err(|_| norito::Error::LengthMismatch)?;
    }
    Ok(text)
}
fn spelling(text: &std::io::Cursor<[u8; 384]>) -> &str {
    core::str::from_utf8(&text.get_ref()[..text.position() as usize])
        .expect("native key roots and hex components are ASCII")
}
fn key(root: &str, components: &[Hex]) -> Result<StatePath, norito::Error> {
    let text = key_text(root, components)?;
    <StatePath as norito::json::JsonObjectKeyOwned>::from_json_key_text(spelling(&text))
        .map_err(norito::json::Error::into_core_error)
}
fn native_key(root: &str, components: &[Hex]) -> StatePath {
    let text = key_text(root, components).expect("fixed native key fits stack buffer");
    // Existing infallible native key APIs retain their original ownership behavior.
    // The bounded query calls only the separate fallible entrypoints below.
    spelling(&text)
        .to_owned()
        .parse()
        .expect("fixed native key is valid")
}
pub(crate) fn uid_binding_native(def: &AssetDefinitionId, account_text: &str) -> StatePath {
    native_key(
        super::asset_uid::BINDING_ROOT,
        &[
            definition(def).expect("fixed definition fits"),
            account(account_text),
        ],
    )
}
pub(crate) fn uid_policy_native(def: &AssetDefinitionId, uid: &[u8; 32]) -> StatePath {
    native_key(
        super::asset_uid::POLICY_ROOT,
        &[definition(def).expect("fixed definition fits"), hex(uid)],
    )
}
pub(crate) fn fi_native(def: &AssetDefinitionId, fi_text: &str) -> StatePath {
    native_key(
        super::asset_fi::FI_ROOT,
        &[
            definition(def).expect("fixed definition fits"),
            account(fi_text),
        ],
    )
}
pub(crate) fn attestation_native(
    def: &AssetDefinitionId,
    account_text: &str,
    fi_text: &str,
    reference: &[u8; 32],
) -> StatePath {
    native_key(
        super::asset_fi::ATTESTATION_ROOT,
        &[
            definition(def).expect("fixed definition fits"),
            account(account_text),
            account(fi_text),
            hex(reference),
        ],
    )
}
pub(crate) fn link_native(def: &AssetDefinitionId, account_text: &str) -> StatePath {
    native_key(
        super::asset_fi::LINK_ROOT,
        &[
            definition(def).expect("fixed definition fits"),
            account(account_text),
        ],
    )
}
pub(crate) fn uid_binding(
    def: &AssetDefinitionId,
    account_text: &str,
) -> Result<StatePath, norito::Error> {
    key(
        super::asset_uid::BINDING_ROOT,
        &[definition(def)?, account(account_text)],
    )
}
pub(crate) fn uid_policy(
    def: &AssetDefinitionId,
    uid: &[u8; 32],
) -> Result<StatePath, norito::Error> {
    key(super::asset_uid::POLICY_ROOT, &[definition(def)?, hex(uid)])
}
pub(crate) fn fi(def: &AssetDefinitionId, fi_text: &str) -> Result<StatePath, norito::Error> {
    key(
        super::asset_fi::FI_ROOT,
        &[definition(def)?, account(fi_text)],
    )
}
pub(crate) fn attestation(
    def: &AssetDefinitionId,
    account_text: &str,
    fi_text: &str,
    reference: &[u8; 32],
) -> Result<StatePath, norito::Error> {
    key(
        super::asset_fi::ATTESTATION_ROOT,
        &[
            definition(def)?,
            account(account_text),
            account(fi_text),
            hex(reference),
        ],
    )
}
pub(crate) fn link(
    def: &AssetDefinitionId,
    account_text: &str,
) -> Result<StatePath, norito::Error> {
    key(
        super::asset_fi::LINK_ROOT,
        &[definition(def)?, account(account_text)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admitted_fi_context_keys_preserve_all_five_existing_native_spellings() {
        let (f, _) = super::super::asset_fi::FiLinkReaderFixture::new();
        let wallet = f.wallet.to_string();
        let fi_text = f.bank.to_string();
        let digest = |value: &str| hex::encode(Hash::new(value.as_bytes()).as_ref());
        let d = digest(&f.definition.to_string());
        let a = digest(&wallet);
        let fhex = digest(&fi_text);
        for reference in [[0; 32], [19; 32], [255; 32]] {
            let values = [
                (
                    uid_binding(&f.definition, &wallet).unwrap(),
                    format!("asset_uid_binding_v1/{d}/{a}"),
                ),
                (
                    uid_policy(&f.definition, &reference).unwrap(),
                    format!("asset_uid_policy_v1/{d}/{}", hex::encode(reference)),
                ),
                (
                    fi(&f.definition, &fi_text).unwrap(),
                    format!("asset_fi_v1/{d}/{fhex}"),
                ),
                (
                    attestation(&f.definition, &wallet, &fi_text, &reference).unwrap(),
                    format!(
                        "asset_fi_link_attestation_v1/{d}/{a}/{fhex}/{}",
                        hex::encode(reference)
                    ),
                ),
                (
                    link(&f.definition, &wallet).unwrap(),
                    format!("asset_fi_link_v1/{d}/{a}"),
                ),
            ];
            for (actual, expected) in values {
                assert_eq!(actual, expected.parse::<StatePath>().unwrap());
            }
            assert_eq!(
                uid_binding(&f.definition, &wallet).unwrap(),
                super::super::asset_uid::binding_key(&f.definition, &f.wallet)
            );
            assert_eq!(
                uid_policy(&f.definition, &reference).unwrap(),
                super::super::asset_uid::policy_key(&f.definition, &reference)
            );
            assert_eq!(
                fi(&f.definition, &fi_text).unwrap(),
                super::super::asset_fi::fi_key(&f.definition, &f.bank)
            );
            assert_eq!(
                attestation(&f.definition, &wallet, &fi_text, &reference).unwrap(),
                super::super::asset_fi::attestation_key(
                    &f.definition,
                    &f.wallet,
                    &f.bank,
                    &reference
                )
            );
            assert_eq!(
                link(&f.definition, &wallet).unwrap(),
                super::super::asset_fi::link_key(&f.definition, &f.wallet)
            );
        }
        let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let refused = norito::core::with_decode_limits_scope(limits, || {
            norito::core::classify_decode_attempt(|| link(&f.definition, &wallet))
        });
        assert!(refused.unwrap_err().into_local_refusal().is_ok());
    }
}

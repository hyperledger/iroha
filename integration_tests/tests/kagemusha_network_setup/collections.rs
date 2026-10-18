//! Complete bounded holder reads for the disposable monetary network.

use std::collections::{BTreeMap, BTreeSet};

use iroha::collections::{Collection, ListQuery, Page};
use norito::json::Value;

use super::*;

/// Read every holder, including unexpected accounts, so conservation cannot hide value.
pub(super) fn holders(client: &iroha::blocking::Client) -> Result<BTreeMap<AccountId, Quantity>> {
    collect_holders(|query| {
        client
            .list_page(&Collection::AssetHolders(definition_id()), query)
            .map_err(Into::into)
    })
}

fn collect_holders(
    mut fetch: impl FnMut(&ListQuery) -> Result<Page<Value>>,
) -> Result<BTreeMap<AccountId, Quantity>> {
    let mut query = ListQuery::new().limit(8);
    let mut cursors = BTreeSet::new();
    let mut balances = BTreeMap::new();
    for _ in 0..32 {
        let page = fetch(&query)?;
        ensure!(
            page.items.len() <= 8,
            "holder page exceeded requested bound"
        );
        for row in &page.items {
            ensure!(
                row["asset"].as_str() == Some(definition_id().to_string().as_str())
                    && row["scope"].as_str() == Some("global"),
                "foreign asset or balance scope in holder page"
            );
            let account = AccountId::parse_encoded(
                row["account_id"]
                    .as_str()
                    .ok_or_else(|| eyre!("holder account missing"))?,
            )?;
            let amount: Quantity = row["quantity"]
                .as_str()
                .ok_or_else(|| eyre!("exact decimal holder quantity required"))?
                .parse()?;
            ensure!(
                balances.insert(account, amount).is_none(),
                "duplicate holder across collection pages"
            );
        }
        let Some(next) = query.next_page(&page) else {
            return Ok(balances);
        };
        ensure!(
            cursors.insert(page.next_cursor.expect("next page has cursor")),
            "holder cursor did not advance"
        );
        query = next;
    }
    Err(eyre!("holder collection exceeded 32 pages"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(seed: u8, amount: &str) -> Value {
        norito::json!({
            "asset": (definition_id().to_string()),
            "scope": "global",
            "account_id": (account(seed).to_string()),
            "quantity": amount,
        })
    }

    #[test]
    fn complete_holder_read_keeps_unknown_accounts_and_empty_cursor_pages() {
        let mut pages = [
            Page {
                items: vec![row(41, "9")],
                next_cursor: Some("one".into()),
                total: None,
            },
            Page {
                items: vec![],
                next_cursor: Some("two".into()),
                total: None,
            },
            Page::last(vec![row(77, "1")]),
        ]
        .into_iter();
        let balances = collect_holders(|_| Ok(pages.next().expect("three pages"))).unwrap();
        assert_eq!(balances.len(), 2);
        assert_eq!(balances[&account(77)], "1".parse::<Quantity>().unwrap());
        assert_eq!(
            balances
                .values()
                .try_fold(Quantity::zero(), |sum, value| sum.checked_add(value))
                .unwrap(),
            quantity()
        );
        assert!(pages.next().is_none());
    }

    #[test]
    fn holder_read_refuses_duplicate_rows_and_stalled_or_unbounded_cursors() {
        let mut first = true;
        assert!(
            collect_holders(|_| {
                let page = Page {
                    items: vec![row(41, "10")],
                    next_cursor: first.then(|| "next".into()),
                    total: None,
                };
                first = false;
                Ok(page)
            })
            .unwrap_err()
            .to_string()
            .contains("duplicate holder")
        );
        assert!(
            collect_holders(|_| Ok(Page {
                items: vec![],
                next_cursor: Some("same".into()),
                total: None
            }))
            .unwrap_err()
            .to_string()
            .contains("did not advance")
        );
        let mut calls = 0;
        assert!(
            collect_holders(|_| {
                calls += 1;
                Ok(Page {
                    items: vec![],
                    next_cursor: Some(calls.to_string()),
                    total: None,
                })
            })
            .unwrap_err()
            .to_string()
            .contains("32 pages")
        );
        assert_eq!(calls, 32);
    }

    #[test]
    fn holder_read_refuses_foreign_scope_asset_and_inexact_quantity() {
        for (field, value) in [
            ("scope", Value::from("dataspace:0")),
            ("asset", Value::from("foreign")),
            ("quantity", Value::from(10)),
            ("account_id", Value::from("alias@domain")),
        ] {
            let mut value_row = row(41, "10");
            value_row
                .as_object_mut()
                .expect("holder object")
                .insert(field.into(), value);
            assert!(
                collect_holders(|_| Ok(Page::last(vec![value_row.clone()]))).is_err(),
                "{field}"
            );
        }
        assert!(
            collect_holders(|_| Ok(Page::last(vec![row(41, "10"); 9])))
                .unwrap_err()
                .to_string()
                .contains("requested bound")
        );
        assert!(
            collect_holders(|_| Err(eyre!("transport failed")))
                .unwrap_err()
                .to_string()
                .contains("transport failed")
        );
    }
}

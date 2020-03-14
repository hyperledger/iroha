//TODO: should be generated DSL
pub struct AssetsQueries {}

impl AssetsQueries {
    pub fn by_id(&self, _asset_id: &str) -> Result<Asset, ()> {
        Ok(Asset {
            account_id: "account2_name@domain".to_string(),
        })
    }
}

pub struct Asset {
    pub account_id: String,
}

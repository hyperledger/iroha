use iroha_data_model::account::AccountId;

fn main() {
    let account_id: AccountId = "alice@wonderland".parse().expect("Valid account id");
    println!("ID: {}", account_id.name);
}

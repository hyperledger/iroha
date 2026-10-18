//! Client-path-like query builder benches using a mock, in-process `QueryExecutor` (no network).

use criterion::Criterion;
use iroha_crypto::KeyPair;
use iroha_data_model::{
    prelude::*,
    query::{
        QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryWithParams,
        account::prelude::FindAccounts,
        builder::{QueryBuilder, QueryExecutor, TypedBatchDowncastError},
        parameters::FetchSize,
    },
};
use nonzero_ext::nonzero;
#[derive(Clone)]
struct MockExec {
    data: Vec<Account>,
    page: usize,
}
impl MockExec {
    fn new(total: usize, page: usize) -> Self {
        let mut v = Vec::with_capacity(total);
        for _ in 0..total {
            let kp = KeyPair::random();
            let acc_id = AccountId::new(kp.public_key().clone());
            let acc = Account::new(acc_id.clone()).build(&acc_id);
            v.push(acc);
        }
        Self { data: v, page }
    }
}
impl QueryExecutor for MockExec {
    type Cursor = usize; // index of next element
    type Error = TypedBatchDowncastError;
    fn execute_singular_query(
        &self,
        _query: iroha_data_model::query::SingularQueryBox,
    ) -> Result<iroha_data_model::query::SingularQueryOutputBox, Self::Error> {
        Err(TypedBatchDowncastError::ColumnCountMismatch {
            expected: 1,
            actual: 0,
        })
    }
    fn start_query(
        &self,
        _query: QueryWithParams,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<u64>, Option<Self::Cursor>), Self::Error> {
        let end = self.page.min(self.data.len());
        let batch = self.data[..end].to_vec();
        let tuple = QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Account(batch));
        let remaining = (self.data.len() - end) as u64;
        let cursor = if end < self.data.len() {
            Some(end)
        } else {
            None
        };
        Ok((tuple, Some(remaining), cursor))
    }
    fn continue_query(
        _cursor: Self::Cursor,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<u64>, Option<Self::Cursor>), Self::Error> {
        let tuple = QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Account(Vec::new()));
        Ok((tuple, Some(0), None))
    }
}
fn bench_builder_iter_1k_fetch_100(c: &mut Criterion) {
    let exec = MockExec::new(1_000, 100);
    c.bench_function("builder_iter_accounts_1k_fetch100", |b| {
        b.iter(|| {
            let builder: QueryBuilder<_, _, Account> = QueryBuilder::new(&exec, FindAccounts)
                .with_fetch_size(FetchSize::new(Some(nonzero!(100_u64))));
            let all = builder.execute_all().unwrap_or_default();
            std::hint::black_box(all.len());
        })
    });
}
fn bench_builder_iter_10k_fetch_500(c: &mut Criterion) {
    let exec = MockExec::new(10_000, 500);
    c.bench_function("builder_iter_accounts_10k_fetch500", |b| {
        b.iter(|| {
            let builder: QueryBuilder<_, _, Account> = QueryBuilder::new(&exec, FindAccounts)
                .with_fetch_size(FetchSize::new(Some(nonzero!(500_u64))));
            let all = builder.execute_all().unwrap_or_default();
            std::hint::black_box(all.len());
        })
    });
}
fn main() {
    // Silence IVM banner if lower layers create it.
    #[allow(unused_imports)]
    {
        use ivm::set_banner_enabled;
        set_banner_enabled(false);
    }
    let mut c = Criterion::default().configure_from_args();
    bench_builder_iter_1k_fetch_100(&mut c);
    bench_builder_iter_10k_fetch_500(&mut c);
    c.final_summary();
}

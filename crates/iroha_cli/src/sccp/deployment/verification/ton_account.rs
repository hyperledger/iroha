//! Strict current TON account/code and getter inspection at one selected masterchain block.

use super::*;
use iroha_sccp::v1::ton_cell::{Cell, TonMinterInitV1, cell_from_boc, minter_account_id};
use iroha_sccp_wallet::pure::ton::{TvmIntV1, TvmStackValueV1};

struct Reader<'a> {
    cell: &'a Cell,
    bit: usize,
    reference: usize,
}

impl<'a> Reader<'a> {
    fn uint(&mut self, width: usize) -> Result<u128> {
        ensure!(
            width <= 128
                && self
                    .bit
                    .checked_add(width)
                    .is_some_and(|end| end <= self.cell.bit_len()),
            "truncated TON account bits"
        );
        let mut value = 0;
        for _ in 0..width {
            value = (value << 1)
                | u128::from(self.cell.data()[self.bit / 8] & (0x80 >> (self.bit % 8)) != 0);
            self.bit += 1;
        }
        Ok(value)
    }
    fn word(&mut self) -> Result<[u8; 32]> {
        let mut word = [0; 32];
        word[..16].copy_from_slice(&self.uint(128)?.to_be_bytes());
        word[16..].copy_from_slice(&self.uint(128)?.to_be_bytes());
        Ok(word)
    }
    fn skip_var_uint(&mut self, prefix: usize, bound: usize) -> Result<()> {
        let bytes = usize::try_from(self.uint(prefix)?)?;
        ensure!(bytes < bound, "noncanonical TON variable integer length");
        self.uint(bytes * 8)?;
        Ok(())
    }
    fn child(&mut self) -> Result<&'a Cell> {
        let child = self
            .cell
            .refs()
            .get(self.reference)
            .and_then(|child| child.cell())
            .ok_or_else(|| eyre!("missing or opaque TON account reference"))?;
        self.reference += 1;
        Ok(child)
    }
}

/// The Account/StorageInfo/StateInit layout in TON's canonical
/// <https://github.com/ton-blockchain/ton/blob/master/crypto/block/block.tlb>.
/// This is an RPC observation, not a TON-finality proof or permission to register a route.
fn account_code(state: &[u8], account: &[u8; 32]) -> Result<SccpTonCodeRefV1> {
    let root = cell_from_boc(state)?;
    let mut reader = Reader {
        cell: &root,
        bit: 0,
        reference: 0,
    };
    ensure!(reader.uint(1)? == 1, "TON account is absent");
    ensure!(
        reader.uint(2)? == 2
            && reader.uint(1)? == 0
            && reader.uint(8)? == 0
            && reader.word()? == *account,
        "TON account address is not the selected basechain account"
    );
    reader.skip_var_uint(3, 7)?; // storage cells
    reader.skip_var_uint(3, 7)?; // storage bits
    match reader.uint(3)? {
        0 => (),
        1 => {
            reader.word()?;
        }
        _ => return Err(eyre!("unknown TON storage-extra layout")),
    }
    reader.uint(32)?;
    if reader.uint(1)? != 0 {
        reader.skip_var_uint(4, 16)?;
    }
    reader.uint(64)?;
    reader.skip_var_uint(4, 16)?;
    if reader.uint(1)? != 0 {
        reader.child()?;
    } // other currencies
    ensure!(reader.uint(1)? == 1, "TON account is not active");
    if reader.uint(1)? != 0 {
        reader.uint(5)?;
    }
    if reader.uint(1)? != 0 {
        reader.uint(2)?;
    }
    ensure!(reader.uint(1)? == 1, "active TON account has no code");
    let code = reader.child()?;
    let reference = SccpTonCodeRefV1 {
        hash: *code.hash(),
        depth: code.depth(),
    };
    if reader.uint(1)? != 0 {
        reader.child()?;
    }
    if reader.uint(1)? != 0 {
        reader.child()?;
    }
    ensure!(
        reader.bit == root.bit_len() && reader.reference == root.refs().len(),
        "trailing TON account state"
    );
    Ok(reference)
}

fn integer(values: &[TvmStackValueV1], index: usize) -> Result<TvmIntV1> {
    match values.get(index) {
        Some(TvmStackValueV1::Integer(value)) => Ok(*value),
        _ => Err(eyre!("missing integer at getter index {index}")),
    }
}
fn uint(values: &[TvmStackValueV1], index: usize) -> Result<u64> {
    integer(values, index)?
        .to_u64()
        .ok_or_else(|| eyre!("getter integer exceeds u64"))
}
fn word(values: &[TvmStackValueV1], index: usize) -> Result<[u8; 32]> {
    integer(values, index)?
        .to_u256()
        .ok_or_else(|| eyre!("getter word is negative"))
}
fn boolean(values: &[TvmStackValueV1], index: usize) -> Result<bool> {
    let value = integer(values, index)?.0;
    if value == [0; 33] {
        Ok(false)
    } else if value == [0xff; 33] {
        Ok(true)
    } else {
        Err(eyre!("getter boolean is not 0 or -1"))
    }
}

fn pristine_state(args: &ConstructorArgsV1, state: &[TvmStackValueV1]) -> Result<CommitteeStateV1> {
    ensure!(state.len() == 24, "get_sccp_state has another arity");
    ensure!(
        boolean(state, 0)? && !boolean(state, 1)?,
        "minter is uninitialized or equivocated"
    );
    ensure!(
        word(state, 2)? == args.taira_network_id
            && word(state, 3)? == args.consensus_instance
            && uint(state, 4)? == u64::from(args.route_revision),
        "minter identity differs from proposal"
    );
    ensure!(
        uint(state, 5)? == args.pin.generation
            && word(state, 6)? == args.pin.committee_root
            && uint(state, 7)? == args.pin.start_height
            && uint(state, 8)? == args.pin.until_ms,
        "minter initial committee differs from proposal"
    );
    for index in [14, 15, 17, 19] {
        ensure!(
            uint(state, index)? == 0,
            "minter nonce, operations or pause deadline is nonzero"
        );
    }
    ensure!(
        !boolean(state, 16)? && !boolean(state, 18)?,
        "minter is paused"
    );
    ensure!(
        word(state, 20)? == [0; 32]
            && word(state, 21)? == [0; 32]
            && word(state, 22)? == word_u128(args.max_wrapped_supply),
        "minter supply or cap differs from pristine proposal"
    );
    uint(state, 23)?;
    Ok(CommitteeStateV1 {
        root: word(state, 9)?,
        until_ms: uint(state, 10)?,
        start: uint(state, 11)?,
        high: uint(state, 12)?,
        generation: uint(state, 13)?,
        equivocated: false,
    })
}

fn checkpoints(values: &[TvmStackValueV1]) -> Result<Vec<(u64, [u8; 32])>> {
    ensure!(values.len() == 7, "get_sccp_checkpoints has another arity");
    let count = usize::try_from(uint(values, 0)?)?;
    ensure!(count <= 3, "too many checkpoint slots");
    let mut result = Vec::new();
    let mut previous = 0;
    for index in 0..3 {
        let height = uint(values, 1 + 2 * index)?;
        let hash = word(values, 2 + 2 * index)?;
        if index < count {
            ensure!(
                height > previous && hash != [0; 32],
                "invalid or reordered checkpoint slot"
            );
            result.push((height, hash));
            previous = height;
        } else {
            ensure!(
                height == 0 && hash == [0; 32],
                "nonzero unused checkpoint slot"
            );
        }
    }
    Ok(result)
}

pub(super) fn verify(
    context: &impl RunContext,
    client: &BlockingClient,
    original: &origin::AuthenticatedOrigin,
    args: &VerifyArgs,
    registration: &SccpRegisterRouteActionV1,
    keys: Vec<[u8; 48]>,
) -> Result<()> {
    use iroha_sccp_rpc::ton::AccountId;
    ensure!(
        args.checkpoint_height.is_empty(),
        "TON reviews all three checkpoint slots automatically"
    );
    let SccpDeploymentV1::Ton(deployment) = registration.deployment else {
        return Err(eyre!("not TON"));
    };
    for (name, code) in [
        ("SccpTairaXorMinter", deployment.minter_code),
        ("SccpTairaXorWallet", deployment.wallet_code),
        ("SccpConsumedBucket", deployment.bucket_code),
    ] {
        require_locked_ton_code(name, code)?;
    }
    let constructor = constructor(original, registration);
    let init = TonMinterInitV1 {
        taira_network_id: original.network,
        consensus_instance: original.instance,
        route_revision: registration.revision,
        max_supply: registration.max_wrapped_supply,
        pin: registration.initial_committee,
        keys,
        wallet_code: deployment.wallet_code,
        bucket_code: deployment.bucket_code,
    };
    ensure!(
        minter_account_id(&init, deployment.minter_code)? == deployment.master_account,
        "proposed minter differs from locked StateInit"
    );
    let lite = ton::connect_config(&context.sccp_config()?, &args.rpc_url)?;
    let at = ton::last_block(&lite)?;
    let state = lite.get_account_state(
        at,
        AccountId {
            workchain: 0,
            address: deployment.master_account,
        },
    )?;
    ensure!(
        state.id == at
            && account_code(&state.state, &deployment.master_account)? == deployment.minter_code,
        "active minter code differs from locked proposal"
    );
    let stack = ton::run_stack_at(&lite, at, &deployment.master_account, "get_sccp_state", &[])?;
    let committee = pristine_state(&constructor, &stack)?;
    verify_committee(
        client,
        original,
        registration.initial_committee.generation,
        &committee,
    )?;
    let points = checkpoints(&ton::run_stack_at(
        &lite,
        at,
        &deployment.master_account,
        "get_sccp_checkpoints",
        &[],
    )?)?;
    if committee.high >= committee.start
        || committee.generation > registration.initial_committee.generation
    {
        ensure!(
            points.iter().any(|(height, _)| *height == committee.high),
            "highest accepted header is absent from checkpoint slots"
        );
    }
    for (height, hash) in points {
        verify_checkpoint(context, client, &args.origin, height, hash)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

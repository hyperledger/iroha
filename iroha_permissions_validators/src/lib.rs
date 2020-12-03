use iroha::{
    permissions::{prelude::*, PermissionsValidator},
    prelude::*,
};
use iroha_data_model::{isi::*, prelude::*};

pub mod public_blockchain {
    use super::*;

    pub struct TransferOnlyOwnedAssets;

    impl PermissionsValidator for TransferOnlyOwnedAssets {
        fn check_instruction(
            &self,
            authority: <Account as Identifiable>::Id,
            instruction: InstructionBox,
            _wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            match instruction {
                InstructionBox::Transfer(TransferBox {
                    source_id: IdBox::AssetId(source_id),
                    object: ValueBox::U32(_),
                    destination_id: IdBox::AssetId(_),
                }) => {
                    if source_id.account_id == authority {
                        Ok(())
                    } else {
                        Err("Can't transfer assets of the other account.".to_string())
                    }
                }
                _ => Ok(()),
            }
        }
    }

    impl From<TransferOnlyOwnedAssets> for PermissionsValidatorBox {
        fn from(_: TransferOnlyOwnedAssets) -> Self {
            Box::new(TransferOnlyOwnedAssets)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn transfer_only_owned_assets() {
            let key_pair = KeyPair::generate().expect("Failed to generate key pair.");
            let peer_id = <Peer as Identifiable>::Id::new("127.0.0.1:7878", &key_pair.public_key);
            let alice_id = <Account as Identifiable>::Id::new("alice", "test");
            let bob_id = <Account as Identifiable>::Id::new("bob", "test");
            let alice_xor_id =
                <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
            let bob_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "bob", "test");
            let wsv = WorldStateView::new(Peer::new(peer_id));
            let transfer = InstructionBox::Transfer(TransferBox {
                source_id: IdBox::AssetId(alice_xor_id),
                object: ValueBox::U32(10),
                destination_id: IdBox::AssetId(bob_xor_id),
            });
            assert!(TransferOnlyOwnedAssets
                .check_instruction(alice_id, transfer.clone(), &wsv)
                .is_ok());
            assert!(TransferOnlyOwnedAssets
                .check_instruction(bob_id, transfer, &wsv)
                .is_err());
        }
    }
}

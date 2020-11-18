use iroha::{
    permissions::{prelude::*, PermissionsValidator},
    prelude::*,
};
use iroha_data_model::{isi::*, prelude::*};

pub mod public_blockchain {
    use super::*;

    pub struct PublicBlockchainPermissions;

    trait ValidateInstruction {
        fn check(
            &self,
            authority: <Account as Identifiable>::Id,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason>;
    }

    impl ValidateInstruction for Transfer<Asset, u32, Asset> {
        fn check(
            &self,
            authority: <Account as Identifiable>::Id,
            _wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            if self.source_id.account_id == authority {
                Ok(())
            } else {
                Err("Can't transfer assets of the other account.".to_string())
            }
        }
    }

    impl PermissionsValidator for PublicBlockchainPermissions {
        fn check_instruction(
            &self,
            authority: <Account as Identifiable>::Id,
            instruction: InstructionBox,
            wsv: &WorldStateView,
        ) -> Result<(), DenialReason> {
            match instruction {
                InstructionBox::Transfer(TransferBox {
                    source_id: IdBox::AssetId(source_id),
                    object: ValueBox::U32(value),
                    destination_id: IdBox::AssetId(destination_id),
                }) => Transfer::<Asset, u32, Asset>::new(source_id, value, destination_id)
                    .check(authority, wsv),
                _ => Ok(()),
            }
        }
    }

    impl From<PublicBlockchainPermissions> for PermissionsValidatorBox {
        fn from(_: PublicBlockchainPermissions) -> Self {
            Box::new(PublicBlockchainPermissions)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn transfer_assets() {
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
            assert!(PublicBlockchainPermissions
                .check_instruction(alice_id, transfer.clone(), &wsv)
                .is_ok());
            assert!(PublicBlockchainPermissions
                .check_instruction(bob_id, transfer, &wsv)
                .is_err());
        }
    }
}

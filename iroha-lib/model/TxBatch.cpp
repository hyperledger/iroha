#include "TxBatch.hpp"

#include "model/converters/pb_common.hpp"
#include "transaction.pb.h"
#include "primitive.pb.h"


namespace iroha_lib {

using namespace iroha::protocol;
using iroha::protocol::Transaction_Payload_BatchMeta_BatchType;

Transaction_Payload_BatchMeta_BatchType TxBatch::getBatchType(bool atomic) const
{
    return atomic ? Transaction_Payload_BatchMeta_BatchType_ATOMIC
                  : Transaction_Payload_BatchMeta_BatchType_ORDERED;
}

TxList TxBatch::batch(std::vector<Transaction>& transactions, bool atomic)
{
    TxList tx_list;

    if (atomic) {
        Transaction::Payload::BatchMeta meta;
        meta.set_type(getBatchType(atomic));

        for (auto& tx: transactions) {
            tx.payload().batch().New()->CopyFrom(meta);
            *tx_list.add_transactions() = tx;
        }
    } else {
        for (const auto& tx: transactions) {
            *tx_list.add_transactions() = tx;
        }
    }
    return tx_list;
}

}

#include "GrpcClient.hpp"


namespace iroha_lib {

template <class Service>
std::shared_ptr<grpc::Channel> createUnauthenticatedChanel(const std::string& address)
{
    return grpc::CreateChannel(
                address,
                grpc::InsecureChannelCredentials());
}


template <class Service>
std::unique_ptr<typename Service::StubInterface> createClient(const std::string& address)
{
    return Service::NewStub(createUnauthenticatedChanel<Service>(address));
}


template <class Service>
std::unique_ptr<typename Service::StubInterface> createClient(
        const std::string& ip,
        const size_t port)
{
    const auto peer_ip = ip + ":" + std::to_string(port);
    return createClient<Service>(peer_ip);
}


GrpcClient::GrpcClient(
        const std::string& target_ip,
        const uint16_t port)
    : command_stub_(createClient<CommandService_v1>(
                                  target_ip,
                                  port)),
      query_stub_(createClient<QueryService_v1>(
                                target_ip,
                                port))
{}

grpc::Status GrpcClient::send(const Transaction& tx)
{
    google::protobuf::Empty empty;
    grpc::ClientContext context;
    return command_stub_->Torii(
                &context,
                tx,
                &empty);
}

grpc::Status GrpcClient::send(const TxList& tx_list)
{
    google::protobuf::Empty empty;
    grpc::ClientContext context;
    return command_stub_->ListTorii(
                &context,
                tx_list,
                &empty);
}

QueryResponse GrpcClient::send(const iroha::protocol::Query& query)
{
    QueryResponse queryResponse;
    grpc::ClientContext context;
    query_stub_->Find(
                &context,
                query,
                &queryResponse);
    return queryResponse;
}

ToriiResponse GrpcClient::getTxStatus(const std::string& tx_hash)
{
    TxStatusRequest statusRequest;
    statusRequest.set_tx_hash(tx_hash);
    ToriiResponse toriiResponse;
    grpc::ClientContext context;
    command_stub_->Status(
                &context,
                statusRequest,
                &toriiResponse);
    return toriiResponse;
}
}  // namespace iroha_lib

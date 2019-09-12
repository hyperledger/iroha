/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "endpoint.grpc.pb.h"
#include "framework/test_client_factory.hpp"
#include "framework/test_logger.hpp"
#include "main/server_runner.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "network/impl/client_factory.hpp"
#include "network/impl/peer_tls_certificates_provider_root.hpp"
#include "network/impl/tls_credentials.hpp"

namespace {
  // two key/cert pairs:
  // one with CN=public_key_1,
  // subjectAltName=IP:127.0.0.1,otherName:1.3.101.112;UTF8:public_key_1
  // another with CN=public_key_2,
  // subjectAltName=IP:127.0.0.1,otherName:1.3.101.112;UTF8:public_key_2

  constexpr auto kPeer1Certificate = R"(-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIUOof8D8aUplguIv1iFTIYSPv9fywwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEVMBMGA1UEAwwMcHVibGljX2tleV8x
MCAXDTE5MDkxMjIwMzgwMVoYDzIxMTkwODE5MjAzODAxWjBcMQswCQYDVQQGEwJB
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRUwEwYDVQQDDAxwdWJsaWNfa2V5XzEwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDQL3vZftv/AjzhdrWM/NIwDZ8DasBbLPWbjNuwELED
2hMySiT0+kKpEUzlkPqGcfIzvxeUy4sBzQfjFCILQJ2ATcLKeYJ42rh6UzdJyqL1
iBUAxQnEq5fU+w4DEznA6j/PI4Unl16721KgdhGJjo/NyXFlsag8JO4nw8QzZNog
FjoppRDwmL+et4s1efsIcO5qaPZdYs/oXBdu8MixukTQUD6mBXwPky/4jB4tbgWU
K0tjzzTtPltPsbfyb9/OJWUo2aERgGufL+BzJfvhd0ngqkdwV7kM3l5PEg+vp+i+
EK27h9GSCCEd70zwEiJAmgTB4vTx7yBtYwKV8dFCetMjAgMBAAGjezB5MB0GA1Ud
DgQWBBSf7UNGeUCU/0Wd7OX41FlK9L+ffjAfBgNVHSMEGDAWgBSf7UNGeUCU/0Wd
7OX41FlK9L+ffjAPBgNVHRMBAf8EBTADAQH/MCYGA1UdEQQfMB2HBH8AAAGgFQYD
K2VwoA4MDHB1YmxpY19rZXlfMTANBgkqhkiG9w0BAQsFAAOCAQEAFePeUAEkKB5K
O6Ud5xzs+cFAZ64oyr035GlaVAGv9eNphuGFHLFOJ1QxepJ/CBiBBxGu/R+0Q33B
WiiS5v3ztfbBznzHIX8VcpBvjpi4HLSNlRSKfyKRXZgHSrqQ/Tmv/qFlweg4BZSn
/ItyDyyDQ9A8nYB4YS+CeND5rtXwno8MP5FvpLpr+uSsQ6QHJzeWzFHkBP6cC4h6
tyChhV7Xa8L8T2Gyj3KJkEXdyTMXtnfsAra+S0MlDdqa2lBGgebZ52lVzqpZxeqC
cuR+sOOdKepbQGtGIsGzA1ZX35Sv+UunmMJOQgCUtGsKFIfyROEMz5nfOhE8hglo
B/dYqhQqAQ==
-----END CERTIFICATE-----)";
  constexpr auto kPeer1Key =
      R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQL3vZftv/Ajzh
drWM/NIwDZ8DasBbLPWbjNuwELED2hMySiT0+kKpEUzlkPqGcfIzvxeUy4sBzQfj
FCILQJ2ATcLKeYJ42rh6UzdJyqL1iBUAxQnEq5fU+w4DEznA6j/PI4Unl16721Kg
dhGJjo/NyXFlsag8JO4nw8QzZNogFjoppRDwmL+et4s1efsIcO5qaPZdYs/oXBdu
8MixukTQUD6mBXwPky/4jB4tbgWUK0tjzzTtPltPsbfyb9/OJWUo2aERgGufL+Bz
Jfvhd0ngqkdwV7kM3l5PEg+vp+i+EK27h9GSCCEd70zwEiJAmgTB4vTx7yBtYwKV
8dFCetMjAgMBAAECggEAfA2Pc07QsOgYdxFRpa2RYej79AFMlgf4YrRQxF1t3am4
/qKH2yK1TiFs/O6jGjIT7RnVZ2jScERIituYXbQnJikwBY7aXEGY4+tqaqJA8KYi
Pc8rvvGxC8x90P9HztjHJRs5YRol7TMHzW4NjTZSIoIC/GIcqZon/7H729Qg1jTV
SxFp6C3jx8I9eRH7wmNKDwTC8Tt2PM2MGSz1zd5G/mxMkOK7EkkOZKjNFBs1p3U5
SdD5mCcTQPTDLJaXMyYwNx02iURFX3nJCklNrcGqc1DsWrTUUiOOIrOqD4Sxlwhd
gvIhm+9BHoXdMOklb10k8bzPYo5/1WWYQGWHbWcUAQKBgQDrtpsntCwAGuQWFt48
sFJr1sTC1cvHHWzzmotYQ+m11cO1xr52R2voR5Z2gzjgf4JSpxEp1Ru7FKEp+dQl
YuwhdFruF9etjld35iA4mS9spEvEkzOwqmpEq1iu9Og/+Zn4y823GJ4I90IZ43gO
bjZoQJfpIfV4qODTCay2goVYowKBgQDiGl3CyPJmKuwLjnj+owONLmh7cSemLA9O
ye1Ml4hQEaDjnel2+SJfR4CQlYRZKkzTFu3mvnQZjqHffBjpKQgaefWTi7G4Fsbj
m49fishZEsKFnphHYBF0CUtSSW2ADB01nA6Bsc+kokqHrILbJ2iJ+UwWb61+GjeT
LScv3XfDgQKBgQDNnADldk13Xf2dox8CU0/iD3qc9b+GlY1nRWTNfpgL7EaGdrHH
HO/ssx11jWt8sN0uWdsn4WQKIamfovRCFHMjj4qN67BQDT0RMmTi2gS7QOlytHC/
ZzfBZLG8E5fPzltX4fc1Ar0/1ucLDBe6hrrg349jZiLouG88x1Cn91x3/wKBgQDB
z5oJatiljStS6Kh8lV1o+pvjHGbBQUlJ3ztDCS12fPXtxqGmMv4ssAzbYt7U07aQ
xzncLes1MRc+i5CK5Homv94qwHbxdsy7s8+dNUhxWexWP1EG9algTss62Og896Ve
G8wvjiyQUfETBWQR2WD5zDFVlhsgWfbDeNP7aprLgQKBgFRU0m8FI6FzD2tsXnE8
hBTGOgd79TjnpSYg3T8jEeAUxEgk061RaaLpnMrxKX9qk0NnCVBkQKo2TFM5QKqA
yoS2xZvEE8lfgHAQaXb2FX0Tc9FeXKXxZZFGvfw23tca78HFtjY4GR9RIhh9UvK5
8CqoT0MHQYjmsajQRfRWpTdJ
-----END PRIVATE KEY-----)";
  constexpr auto kPeer2Certificate = R"(-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIUGVDHJ8YKBVEvr7v9ylFwF9eXO1owDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEVMBMGA1UEAwwMcHVibGljX2tleV8y
MCAXDTE5MDkxMjIwMTc0N1oYDzIxMTkwODE5MjAxNzQ3WjBcMQswCQYDVQQGEwJB
VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0
cyBQdHkgTHRkMRUwEwYDVQQDDAxwdWJsaWNfa2V5XzIwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDMVy3yLkQjvGTP4SGrRQ70ugo2So+7Vgr1b93EhxKf
5Z4XZA4TOYUrcStBqQcjs4xMQ9EOsHUt7+VFtPwz1PvO2wqfrZ6Rn6h1fzuSWCpM
fpBFgcnLQNW8gpnj7YZ/hE3QtKXT5lnbDdB8QAxNrZX34ShCFqcPJAe80Nu4nT3z
F+sh/4vjPtRMvLslGLOK2AKDhHn9AYTAgUzpeOwDwGx+KEpj7OCNcRfe15xrDAh3
+c8ezHI4H982koudve4mWNSkfLCtL/KdeB88m8fDMTjk/Q7HBMrl7pLAnwkkFGG2
MXWRwwZSoSxYORpDfqKoNayVnD3h5xk2UlzoUwdseEqDAgMBAAGjezB5MB0GA1Ud
DgQWBBQlEpN42nTInVYwNcgowEiaV/TqrDAfBgNVHSMEGDAWgBQlEpN42nTInVYw
NcgowEiaV/TqrDAPBgNVHRMBAf8EBTADAQH/MCYGA1UdEQQfMB2HBH8AAAGgFQYD
K2VwoA4MDHB1YmxpY19rZXlfMjANBgkqhkiG9w0BAQsFAAOCAQEATAbRGTQF0Qfc
T08eBTvHXq0MhlxD7SrcMELG6vktaQ1Rnla6Ad7XhN5WwcY6mMVJHx0GprqsyphB
uXP2SACTyhBmOhze+TFC4DjOflk6S+aFaHFMMSAvnqV4qaPjaaRvL58l0pGMzS4V
NOLthpOq3AZZTWE1KzkNEj/+SqYZXnoXqAXRmpm0Ng2eevUhR76NsJivl5msqie+
97G1AoYAkkJGnbzUz/+4+oB9vDgkuG9qmT6BGAE5CoXADd9Bf61s4ZyaMA+feJ55
rz/b1L5tZYIXibBsw1S2Nzy9clRLWiNSMKp+X0/7b11X3Fj/LT7lSvEwcQSAwBS0
+AVODvOGKw==
-----END CERTIFICATE-----)";
  constexpr auto kPeer2Key = R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMVy3yLkQjvGTP
4SGrRQ70ugo2So+7Vgr1b93EhxKf5Z4XZA4TOYUrcStBqQcjs4xMQ9EOsHUt7+VF
tPwz1PvO2wqfrZ6Rn6h1fzuSWCpMfpBFgcnLQNW8gpnj7YZ/hE3QtKXT5lnbDdB8
QAxNrZX34ShCFqcPJAe80Nu4nT3zF+sh/4vjPtRMvLslGLOK2AKDhHn9AYTAgUzp
eOwDwGx+KEpj7OCNcRfe15xrDAh3+c8ezHI4H982koudve4mWNSkfLCtL/KdeB88
m8fDMTjk/Q7HBMrl7pLAnwkkFGG2MXWRwwZSoSxYORpDfqKoNayVnD3h5xk2Ulzo
UwdseEqDAgMBAAECggEBAJS5z0M50XaBJI75OVxDA0O0NMKXOk4LriY9qZflB/VB
VvOHa4cqknawA9/iesPNZwwLQBoE7QTmWmWF+RpwpmZEn1LhN0yefCoo1N8LNJ5A
cBlnAczh/68ZD5EJzJ77WPfSw++a9UOuplQI+et/sGuegYK4ohcvDkKrcYDJUdGg
Bg2lWnK71pCVrVi0ZhANjmaTU4XLrJxo0ASfTl2if5QURF832sU+gLsi6dTcb47o
WWHiZNk/xFcSsjkdLZi3rFiJJB0qymmQOVLPxdfRhOiBwiduh6mp0yUTarJkwEJ/
TwtWw2PUirrAPaZzJBUi+kUksD1U32dF1h0FLmh184ECgYEA6WlnGyBuXb4R+5mO
NCrpFWQIzsTxdsKqNmQrs6FsBcnGASklo3ghj5yBR/znR37jBkqtjhusBZA4pFGc
xna+m74WcAyyNPR3R9IUPegeOWVTX6o0OyERVgorsKI3qU8DtaAY2o+5RpGfyfXJ
n1deZe5MZBX41CqRiBj32LbqYjECgYEA4B2PcfD1CWoKyJHzTvwMC2Q2d8FfiTFw
wAU66fVQJOSUTYweEGHK5TnhhRkpu2UdLiSq/qsZzpQsYqwSLXjU/p1WZ+vpkwuW
4kMscsfHQbyNRKuXZgN/l3C12nC77NopNjy6Fc7Bm3WFijrat7+pRjk7bYDwU58e
+vbAuhFC9vMCgYB8KXONfIz5FNigDCkXGxRuKo5830rLL/Y3hMWyglXiJllL2MWK
1aaUrF4hGyk0YQ0HFcaI57N0KinXTwqkkBoI4u8wn7BUdw7Uh6342HbrdTkKlJHA
OnDsYfCnv0L4r217ujQ+X2HhZimn1zVvq5wtgLvmKcH5qsNLsGx3PaYkoQKBgQCC
a3FggzJ1igpAcf6/RhnUPzsbMaLg+a59cA26vJEpBwPupM2SBvbFsos0o1IPxWXX
xmrjzLo15zB1M2FYqOp6SSFRVI4WjjX98c1Z9jxUWt9yyNBQA1Uq0eJh/hy+Vq6I
64n2yt0MFLXjnSBOsfBV91RIAzLX1s92iEXbgdQQVQKBgHA8JHgOdGg2748/wlds
uhN5ls5koFWPU8bzGWGvAJcb0vGEKoqfaETgVslt7uk6RzN0UkOwvZ0WgilKlZtO
0IBXlLIQNZhodyWpBoPsIV7aLZeGmJq0Mysd9le417QjpXtFgvNjAKpNMAOuT2qt
b+PKVx014xoU/gTAWXHHx7AZ
-----END PRIVATE KEY-----)";

  constexpr auto kLocalhost = "127.0.0.1";
  constexpr auto kLocalhostAnyPort = "127.0.0.1:0";

  class MockQueryService : public iroha::protocol::QueryService_v1::Service {
   public:
    grpc::Status Find(grpc::ServerContext *context,
                      const iroha::protocol::Query *request,
                      iroha::protocol::QueryResponse *response) override {
      return grpc::Status::OK;
    }
  };
}  // namespace

class ClientFactoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    insecure_client_factory_ = iroha::network::getTestInsecureClientFactory();
    insecure_server_runner_ = std::make_unique<iroha::network::ServerRunner>(
        kLocalhostAnyPort, getTestLogger("InsecureServerRunner"), false);
    insecure_server_runner_->append(std::make_shared<MockQueryService>());
    auto insecure_port_optional =
        iroha::expected::resultToOptionalValue(insecure_server_runner_->run());
    ASSERT_TRUE(insecure_port_optional) << "Could not create insecure server";
    insecure_address_ =
        std::string(kLocalhost) + ":" + std::to_string(*insecure_port_optional);

    auto client_credentials =
        std::make_shared<iroha::network::TlsCredentials>();
    client_credentials->private_key = kPeer1Key;
    client_credentials->certificate = kPeer1Certificate;
    auto server_credentials =
        std::make_shared<iroha::network::TlsCredentials>();
    server_credentials->private_key = kPeer2Key;
    server_credentials->certificate = kPeer2Certificate;
    auto server_cert_provider =
        std::make_shared<iroha::network::PeerTlsCertificatesProviderRoot>(
            kPeer1Certificate);

    tls_client_factory_ = iroha::network::getTestTlsClientFactory(
        std::string(kPeer2Certificate),
        boost::make_optional<
            std::shared_ptr<const iroha::network::TlsCredentials>>(
            client_credentials));
    tls_server_runner_ = std::make_unique<iroha::network::ServerRunner>(
        kLocalhostAnyPort,
        getTestLogger("TlsServerRunner"),
        false,
        boost::make_optional<
            std::shared_ptr<const iroha::network::TlsCredentials>>(
            server_credentials),
        boost::make_optional<
            std::shared_ptr<const iroha::network::PeerTlsCertificatesProvider>>(
            server_cert_provider));
    tls_server_runner_->append(std::make_shared<MockQueryService>());
    auto tls_port_optional =
        iroha::expected::resultToOptionalValue(tls_server_runner_->run());
    ASSERT_TRUE(tls_port_optional) << "Could not create TLS server";
    tls_address_ =
        std::string(kLocalhost) + ":" + std::to_string(*tls_port_optional);
  }

  auto makeRequestAndCheckStatus(
      const std::shared_ptr<iroha::protocol::QueryService_v1::StubInterface>
          &client,
      grpc::StatusCode code) {
    iroha::protocol::Query query;
    iroha::protocol::QueryResponse response;

    grpc::ClientContext client_context;

    auto status = client->Find(&client_context, query, &response);

    ASSERT_EQ(status.error_code(), code) << status.error_message();
  }

  auto makeClient(bool secure_client,
                  bool secure_server,
                  const std::string &tls_certificate = kPeer2Certificate) {
    return (secure_client ? tls_client_factory_ : insecure_client_factory_)
        ->createClient<iroha::protocol::QueryService_v1>(
            *makePeer(secure_server ? tls_address_ : insecure_address_,
                      shared_model::crypto::PublicKey(""),
                      tls_certificate));
  }

  std::string insecure_address_;
  std::unique_ptr<iroha::network::ServerRunner> insecure_server_runner_;
  std::unique_ptr<iroha::network::GenericClientFactory>
      insecure_client_factory_;

  std::string tls_address_;
  std::unique_ptr<iroha::network::ServerRunner> tls_server_runner_;
  std::unique_ptr<iroha::network::GenericClientFactory> tls_client_factory_;
};

TEST_F(ClientFactoryTest, InsecureConnectionToInsecureServer) {
  makeRequestAndCheckStatus(makeClient(false, false), grpc::OK);
}

TEST_F(ClientFactoryTest, SecureConnectionToInsecureServer) {
  makeRequestAndCheckStatus(makeClient(true, false), grpc::UNAVAILABLE);
}

TEST_F(ClientFactoryTest, InsecureConnectionToSecureServer) {
  makeRequestAndCheckStatus(makeClient(false, true), grpc::UNAVAILABLE);
}

TEST_F(ClientFactoryTest, SecureConnectionToSecureServer) {
  makeRequestAndCheckStatus(makeClient(true, true), grpc::OK);
}

// TODO: mix & match wrong certificates and keys

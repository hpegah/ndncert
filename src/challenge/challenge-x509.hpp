#ifndef NDNCERT_CHALLENGE_POSSESSION_HPP
#define NDNCERT_CHALLENGE_POSSESSION_HPP

#include "challenge-module.hpp"

#include <ndn-cxx/security/key-chain.hpp>

namespace ndncert {

/**
 * @brief Provide Possession based challenge
 *
 * Possession here means possession of the certificate issued by a trust anchor. Once the requester
 * could proof his/her possession of an existing certificate from this or other certificate issuer,
 * the requester could finish the challenge.
 *
 * The requester needs to provide the proof of the possession of a certificate issued by
 * a trust anchor. The challenge require the requester to pass the BASE64 certificate and
 * a BASE64 Data packet signed by the credential pub key and whose content is the request id.
 *
 * The main process of this challenge module is:
 *   1. Requester provides a certificate signed by that trusted certificate as credential.
 *   2. The challenge module will verify the signature of the credential.
 *   3. The challenge module will Provide a 16 octet random number data.
 *   3. The Requester signs the signed Data to prove it possess the private key
 *
 * Failure info when application fails:
 *   INVALID_PARAMETER: When the cert issued from trust anchor or self-signed cert
 *     cannot be validated.
 *   FAILURE_INVALID_FORMAT: When the credential format is wrong.
 */
class ChallengeX509Possession : public ChallengeModule
{
public:
  explicit
  ChallengeX509Possession(const std::string& configPath = "");

  // For CA
  std::tuple<ErrorCode, std::string>
  handleChallengeRequest(const Block& params, ca::RequestState& request) override;

  // For Client
  std::multimap<std::string, std::string>
  getRequestedParameterList(Status status, const std::string& challengeStatus) override;

  Block
  genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                         const std::multimap<std::string, std::string>& params) override;

  static void
  fulfillParameters(std::multimap<std::string, std::string>& params,
                    ndn::KeyChain& keyChain, const Name& issuedCertName,
                    ndn::span<const uint8_t, 16> nonce);

  // challenge parameters
  static const std::string PARAMETER_KEY_CREDENTIAL_CERT;
  static const std::string PARAMETER_KEY_NONCE;
  static const std::string PARAMETER_KEY_PROOF;
  static const std::string NEED_PROOF;

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  void
  parseConfigFile();

NDNCERT_PUBLIC_WITH_TESTS_ELSE_PRIVATE:
  std::list<Certificate> m_trustAnchors;
  std::string m_configFile;
};

} // namespace ndncert

#endif // NDNCERT_CHALLENGE_X509_HPP

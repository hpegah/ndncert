/*
 * Copyright (c) 2017-2024, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "challenge-x509.hpp"

#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/util/random.hpp>

#include <boost/property_tree/json_parser.hpp>

#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>

namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.x509possession);
NDNCERT_REGISTER_CHALLENGE(ChallengeX509Possession, "x509_possession");

const std::string ChallengeX509Possession::PARAMETER_KEY_CREDENTIAL_CERT = "issued-cert";
const std::string ChallengeX509Possession::PARAMETER_KEY_NONCE = "nonce";
const std::string ChallengeX509Possession::PARAMETER_KEY_PROOF = "proof";
const std::string ChallengeX509Possession::NEED_PROOF = "need-proof";

ChallengeX509Possession::ChallengeX509Possession(const std::string& configPath)
  : ChallengeModule("x509_possession", 1, time::seconds(60))
{
  if (configPath.empty()) {
    m_configFile = std::string(NDNCERT_SYSCONFDIR) + "/ndncert/challenge-credential.conf";
  }
  else {
    m_configFile = configPath;
  }
}

void
ChallengeX509Possession::parseConfigFile()
{
  JsonSection config;
  try {
    boost::property_tree::read_json(m_configFile, config);
  }
  catch (const boost::property_tree::file_parser_error& error) {
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + m_configFile + ": " +
                                 error.message() + " on line " + std::to_string(error.line())));
  }

  if (config.begin() == config.end()) {
    NDN_THROW(std::runtime_error("Error processing configuration file: " + m_configFile + " no data"));
  }

  m_trustAnchors.clear();
  auto anchorList = config.get_child("anchor-list");
  auto it = anchorList.begin();
  for (; it != anchorList.end(); it++) {
    std::istringstream ss(it->second.get("certificate", ""));
    auto cert = ndn::io::load<Certificate>(ss);
    if (cert == nullptr) {
      NDN_LOG_ERROR("Cannot load the certificate from config file");
      continue;
    }
    m_trustAnchors.push_back(*cert);
  }
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengeX509Possession::handleChallengeRequest(const Block& params, ca::RequestState& request)
{
  NDN_LOG_TRACE("starting x.509 challenge");
  params.parse();
  if (m_trustAnchors.empty()) {
    parseConfigFile();
  }

  FILE *fp = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *chain = sk_X509_new_null();
  EVP_PKEY* publicKey = NULL;
  int num_certs = 0;
  X509 *server_cert = NULL;

  const uint8_t* signature = nullptr;
  size_t signatureLen = 0;

  std::array<uint8_t, 16> secretCode{};

  NDN_LOG_TRACE("params size is: " << params.size());
  const auto& elements = params.elements();
  for (size_t i = 0; i < elements.size() - 1; i++) {
    if (elements[i].type() == tlv::ParameterKey && elements[i + 1].type() == tlv::ParameterValue) {
      if (readString(elements[i]) == PARAMETER_KEY_CREDENTIAL_CERT) {
        try {
          // Block testCert = elements[i+1].blockFromValue();
          // std::string testString (testCert.begin(), testCert.end());
          // NDN_LOG_TRACE("testing block to string conversion: " << testString);
          auto block = elements[i+1].value_bytes();
          NDN_LOG_TRACE("Creating block");
          NDN_LOG_TRACE("Block size is: " << block.size());
          // std::string fileName (block.begin(), block.end());
          // NDN_LOG_TRACE("converting to string " << fileName);
          // fileName = "/Users/hopepegah/Desktop/avinc-com-chain.pem";
          // NDN_LOG_TRACE("filename is: " << fileName);
          // const char* certChainFile = NULL;
          // certChainFile = "/Users/hopepegah/Desktop/avinc-com-chain.pem";
          // NDN_LOG_TRACE("converting to character array");
          // fp = fopen(certChainFile, "r");
          // NDN_LOG_TRACE("attempting to open file");
          // if(!fp){
          //   NDN_LOG_TRACE("file did not open");
          // }
          // reads in the certificate and converts from base64
          std::string certString (block.begin(), block.end());
          NDN_LOG_TRACE("Cert chain is: " << certString);
          BIO* bio = BIO_new_mem_buf(certString.data(), static_cast<int>(certString.size()));
          NDN_LOG_TRACE("Cert string size is: " << static_cast<int>(certString.size()));
          X509* cert = nullptr;
          NDN_LOG_TRACE("Created cert pointer");
          // Add the certificate to the stack
          while ((cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) != nullptr) {
            char* subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
            NDN_LOG_TRACE("push cert: " << subject);
            sk_X509_push(chain, cert); // Add the certificate to the stack
          }
          BIO_free(bio);
          // while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
          //   char* subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
          //   NDN_LOG_TRACE("push cert: " << subject);
          //   sk_X509_push(chain, cert);
          // }
          // fclose(fp);
          
          // finds the number of certs in the chains
          num_certs = sk_X509_num(chain);
          NDN_LOG_TRACE("there are " << num_certs << " certs in this x.509 chain");
          // stores the first certificate in the key chain, which is the server certificate
          server_cert = sk_X509_value(chain, 0);
          publicKey = X509_get_pubkey(server_cert);

          NDN_LOG_TRACE("the public key of the server certificate is: " << &publicKey);

        }
        catch (const std::exception& e) {
          NDN_LOG_ERROR("Cannot load challenge parameter: credential " << e.what());
          return returnWithError(request, ErrorCode::INVALID_PARAMETER,
                                 "Cannot challenge credential: credential."s + e.what());
        }
      }
      else if (readString(elements[i]) == PARAMETER_KEY_PROOF) {
        signature = elements[i + 1].value();
        NDN_LOG_TRACE("Signature is: " << signature);
        signatureLen = elements[i + 1].value_size();
      }
    }
  }

  Certificate credential;

  // verify the credential and the self-signed cert
  if (request.status == Status::BEFORE_CHALLENGE) {
    NDN_LOG_TRACE("Challenge Interest arrives. Check certificate and init the challenge");

    // check the certificate chain validity
    // check the certificate signature chain
    X509_STORE *store = X509_STORE_new();
    X509 *root_cert = sk_X509_value(chain, sk_X509_num(chain) - 1);
    X509_STORE_add_cert(store, root_cert);

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, sk_X509_value(chain, 0), chain);

    int result = X509_verify_cert(ctx);
    bool is_valid = (result == 1);

    if (!is_valid) {
        int error = X509_STORE_CTX_get_error(ctx);
        NDN_LOG_TRACE("Certificate verification failed: " << X509_verify_cert_error_string(error));
        return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Certificate cannot be verified");
    } else{
        NDN_LOG_TRACE("Certificate chain is verified and valid");
    }

    // Convert the certificate to DER format
    int len = i2d_X509(server_cert, nullptr);
    if (len < 0) {
        NDN_LOG_TRACE("Failed to convert certificate to DER format.");
    }

    std::vector<uint8_t> der(len);
    unsigned char* derPtr = der.data();
    i2d_X509(server_cert, &derPtr);

    NDN_LOG_TRACE("Converted server cert to DER format.");

    // for the first time, init the challenge
    // generate a random secret code
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);

    NDN_LOG_TRACE("Starting random secret code generation");

    for (auto& byte : secretCode) {
        byte = dis(gen);
    }

    NDN_LOG_TRACE("The random secret code is: " << ndn::toHex(secretCode));

    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_NONCE, ndn::toHex(secretCode));
    secretJson.add(PARAMETER_KEY_CREDENTIAL_CERT, ndn::toHex(der));
    NDN_LOG_TRACE("Secret for request " << ndn::toHex(request.requestId) << " : " << ndn::toHex(secretCode));
    return returnWithNewChallengeStatus(request, NEED_PROOF, std::move(secretJson), m_maxAttemptTimes, m_secretLifetime);
  }
  else if (request.challengeState && request.challengeState->challengeStatus == NEED_PROOF) {
    NDN_LOG_TRACE("Challenge Interest (proof) arrives. Check the proof");
    //check the format and load credential
    if (signatureLen == 0) {
      return returnWithError(request, ErrorCode::BAD_INTEREST_FORMAT, "Cannot find certificate");
    }
    auto secretCode = *ndn::fromHex(request.challengeState->secrets.get(PARAMETER_KEY_NONCE, ""));

    //check the proof
    // Convert public key to PKCS#8 format in PEM encoding
    BIO* bio = BIO_new(BIO_s_mem());  // Create a memory BIO to hold the output
    if (PEM_write_bio_PUBKEY(bio, publicKey) == 0) {
        NDN_LOG_TRACE("Failed to write public key in PKCS#8 format.");
    }

    // Read the PEM data from the BIO
    BUF_MEM* buffer;
    BIO_get_mem_ptr(bio, &buffer);
    //  stores the server certificate public key as a pkcs8 format
    std::string pkcs8PubKey(buffer->data, buffer->length);


    ndn::security::transform::PublicKey key;
    key.loadPkcs8(credential.getPublicKey());

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    NDN_LOG_TRACE("attempting to verify signature against server cert");

    // openssl function to verify the signature of the secret code ** assumes SHA256 was used for signature
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey) == 1 &&
        EVP_DigestVerify(ctx, signature, signatureLen, secretCode.data(), secretCode.size()) == 1) {
        return returnWithSuccess(request);
    }
    NDN_LOG_TRACE("Cannot verify the proof of private key against credentation");
    return returnWithError(request, ErrorCode::INVALID_PARAMETER,
                           "Cannot verify the proof of private key against credential.");
  }

  NDN_LOG_TRACE("Proof of possession: bad state");
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Fail to recognize the request.");
}

// For Client
std::multimap<std::string, std::string>
ChallengeX509Possession::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  if (status == Status::BEFORE_CHALLENGE) {
    result.emplace(PARAMETER_KEY_CREDENTIAL_CERT, "Please provide the file path for the certificate issued by a trusted CA.");
    return result;
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_PROOF) {
    result.emplace(PARAMETER_KEY_PROOF, "Please sign a Data packet with request ID as the content.");
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  return result;
}

Block
ChallengeX509Possession::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                            const std::multimap<std::string, std::string>& params)
{
  Block request(tlv::EncryptedPayload);
  if (status == Status::BEFORE_CHALLENGE) {
    if (params.size() != 1) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    NDN_LOG_TRACE("trying to create request");
    for (const auto& item : params) {
      if (std::get<0>(item) == PARAMETER_KEY_CREDENTIAL_CERT) {
        request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_CREDENTIAL_CERT));
        Block valueBlock(tlv::ParameterValue);
        auto& certTlvStr = std::get<1>(item);
        // Block testBlock = Block(ndn::make_span(reinterpret_cast<const uint8_t*>(certTlvStr.data()), certTlvStr.size()));
        valueBlock = (ndn::makeStringBlock(tlv::ParameterValue, certTlvStr));
        //testBlock.encode();
        // NDN_LOG_TRACE("test block size: " << testBlock.value_size());
        // valueBlock.push_back(testBlock);
        valueBlock.encode();
        NDN_LOG_TRACE("certTlvStr size: " << certTlvStr.size());
        request.push_back(valueBlock);
        NDN_LOG_TRACE("value block size: " << valueBlock.value_size());
      }
      else {
        NDN_THROW(std::runtime_error("Wrong parameter provided."));
      }
    }
  }
  else if (status == Status::CHALLENGE && challengeStatus == NEED_PROOF) {
    if (params.size() != 1) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    request.push_back(ndn::makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
    for (const auto& item : params) {
      if (std::get<0>(item) == PARAMETER_KEY_PROOF) {
        request.push_back(ndn::makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_PROOF));
        request.push_back(ndn::makeStringBlock(tlv::ParameterValue, std::get<1>(item)));
      }
      else {
        NDN_THROW(std::runtime_error("Wrong parameter provided."));
      }
    }
  }
  else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  NDN_LOG_TRACE("request size: " << request.value_size());
  return request;
}

void
ChallengeX509Possession::fulfillParameters(std::multimap<std::string, std::string>& params,
                                       ndn::KeyChain& keyChain, const Name& issuedCertName,
                                       ndn::span<const uint8_t, 16> nonce)
{
  auto keyName = ndn::security::extractKeyNameFromCertName(issuedCertName);
  auto id = keyChain.getPib().getIdentity(ndn::security::extractIdentityFromCertName(issuedCertName));
  auto issuedCert = id.getKey(keyName).getCertificate(issuedCertName);
  const auto& issuedCertTlv = issuedCert.wireEncode();
  auto signature = keyChain.getTpm().sign({nonce}, keyName, ndn::DigestAlgorithm::SHA256);

  for (auto& [key, val] : params) {
    if (key == PARAMETER_KEY_CREDENTIAL_CERT) {
      val = std::string(reinterpret_cast<const char*>(issuedCertTlv.data()), issuedCertTlv.size());
    }
    else if (key == PARAMETER_KEY_PROOF) {
      val = std::string(signature->get<char>(), signature->size());
    }
  }
}

} // namespace ndncert

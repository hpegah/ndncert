/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2020, Regents of the University of California.
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

#ifndef NDNCERT_CONFIGURATION_HPP
#define NDNCERT_CONFIGURATION_HPP

#include "detail/ca-request-state.hpp"
#include "name-assignment/assignment-func.hpp"

namespace ndn {
namespace ndncert {

struct CaProfile {
public:
  /**
   * Parse the configuration json and modify current struct to the result.
   * @param configJson the configuration json to parse
   */
  void
  parse(const JsonSection& configJson);

  /**
   * @return the JSON representation of this profile.
   */
  JsonSection
  toJson() const;

public:
  /**
   * CA Name prefix (without /CA suffix).
   */
  Name m_caPrefix;
  /**
   * CA Information.
   * Default: "".
   */
  std::string m_caInfo;
  /**
   * A list of parameter-keys for PROBE.
   * Default: empty list.
   */
  std::list<std::string> m_probeParameterKeys;
  /**
   * Maximum allowed validity period of the certificate being requested.
   * The value is in the unit of second.
   * Default: one day (86400 seconds).
   */
  time::seconds m_maxValidityPeriod;
  /**
   * Maximum allowed suffix length of requested name.
   * E.g., When its value is 2, at most 2 name components can be assigned after m_caPrefix.
   * Default: none.
   */
  optional<size_t> m_maxSuffixLength = nullopt;
  /**
   * A list of supported challenges. Only CA side will have m_supportedChallenges.
   * Default: empty list.
   */
  std::list<std::string> m_supportedChallenges;
  /**
   * CA's certificate. Only Client side will have m_cert.
   * Default: nullptr.
   */
  std::shared_ptr<security::Certificate> m_cert;

private:
  void
  parseProbeParameters(const JsonSection& section);

  void
  parseChallengeList(const JsonSection& configSection);
};

namespace ca {

/**
 * @brief CA's configuration on NDNCERT.
 * @sa https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3#213-ca-profile
 *
 * The format of CA configuration in JSON
 * {
 *  "ca-prefix": "",
 *  "ca-info": "",
 *  "max-validity-period": "",
 *  "max-suffix-length": "",
 *  "probe-parameters":
 *  [
 *    {"probe-parameter-key": ""},
 *    {"probe-parameter-key": ""}
 *  ]
 *  "supported-challenges":
 *  [
 *    {"challenge": ""},
 *    {"challenge": ""}
 *  ]
 * }
 */
class CaConfig
{
public:
  /**
   * Load CA configuration from the file.
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const std::string& fileName);

public:
  CaProfile m_caItem;
  /**
   * Used for CA redirection
   * @sa https://github.com/named-data/ndncert/wiki/NDNCERT-Protocol-0.3-PROBE-Extensions#probe-extension-for-redirection
   */
  optional<std::vector<std::shared_ptr<security::Certificate>>> m_redirection = nullopt;
  /**
   * Name Assignment Functions
   */
  std::vector<std::unique_ptr<NameAssignmentFunc>> m_nameAssignmentFuncs;
};

} // namespace ca

namespace requester {

/**
 * @brief Represents Client configuration
 * @sa https://github.com/named-data/ndncert/wiki/Client-Configuration-Sample
 */
class ProfileStorage
{
public:
  /**
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const std::string& fileName);

  /**
   * @throw std::runtime_error when config file cannot be correctly parsed.
   */
  void
  load(const JsonSection& configSection);

  void
  save(const std::string& fileName) const;

  void
  removeCaProfile(const Name& caName);

  /**
   * Be cautious. This will add a new trust anchor for requesters.
   */
  void
  addCaProfile(const CaProfile& profile);

  const std::list<CaProfile>&
  getCaItems() const;

private:
  std::list<CaProfile> m_caItems;
};

} // namespace requester
} // namespace ndncert
} // namespace ndn

#endif // NDNCERT_CONFIGURATION_HPP

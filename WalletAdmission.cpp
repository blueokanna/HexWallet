#include "WalletAdmission.h"

#include <stdio.h>
#include <string.h>

#include "WalletCatalog.h"
#include "WalletNetworks.h"
#include "WalletSecurity.h"

namespace hexwallet
{
  namespace
  {
    constexpr RefusedChain kRefusedChains[] = {
        {"aion", "Aion", 425,
         "out of scope by decision; the chain is dormant",
         "a product decision to carry it"},
        {"beam", "Beam", 1533,
         "native CLI single-input transfers implemented; general wallet admission pending",
         "secure key custody, unspent-output discovery and node acceptance with two physical devices"},
        {"ironfish", "Iron Fish", 1338,
         "Sapling-style shielded notes need note decryption, nullifiers and zk proof generation",
         "a zk proof system that fits this MCU, which does not exist today"},
        {"xelis", "Xelis", 0,
         "native key recovery, Ristretto255 accounts and Schnorr primitives implemented; custody unavailable",
         "private on-device recovery, confidential balance synchronization and reviewed confidential transfers"},
        {"qubitcoin", "Qubitcoin", 0,
         "no SLIP-0044 coin type, two unrelated projects publish under ticker QTC, and the owner dropped it from scope",
         "nothing: out of scope by decision, so no row and no adapter"},
        {"qubic", "Qubic", 83293,
         "identity is a FourQ point hashed with KangarooTwelve; an Ed25519/SHA3 substitute would not be the same key",
         "FourQ, KangarooTwelve and SchnorrQ with their official vectors"},
    };

  }

  size_t refused_chain_count()
  {
    return sizeof(kRefusedChains) / sizeof(kRefusedChains[0]);
  }

  const RefusedChain &refused_chain_at(size_t index)
  {
    return kRefusedChains[index];
  }

  const RefusedChain *find_refused_chain(const char *id)
  {
    if (id == nullptr)
      return nullptr;
    for (const RefusedChain &refused : kRefusedChains)
    {
      if (strcmp(refused.id, id) == 0)
        return &refused;
    }
    return nullptr;
  }

  bool chain_is_refused(const char *id)
  {
    return find_refused_chain(id) != nullptr;
  }

  bool refused_chain_describe(const char *id, char *out, size_t out_size)
  {
    const RefusedChain *refused = find_refused_chain(id);
    if (refused == nullptr || out == nullptr || out_size == 0)
      return false;
    char coin_type[12] = {};
    if (refused->slip44 == 0)
      snprintf(coin_type, sizeof(coin_type), "none");
    else
      snprintf(coin_type, sizeof(coin_type), "%lu",
               static_cast<unsigned long>(refused->slip44));
    const int written =
        snprintf(out, out_size, "id=%s name=\"%s\" slip44=%s blocker=\"%s\" requires=\"%s\"",
                 refused->id, refused->name, coin_type, refused->blocker,
                 refused->requirement);
    if (written < 0 || static_cast<size_t>(written) >= out_size)
    {
      out[0] = '\0';
      return false;
    }
    return true;
  }

  bool run_admission_self_tests()
  {
    for (size_t index = 0; index < refused_chain_count(); ++index)
    {
      const RefusedChain &refused = kRefusedChains[index];
      if (refused.id == nullptr || refused.name == nullptr ||
          refused.blocker == nullptr || refused.blocker[0] == '\0' ||
          refused.requirement == nullptr || refused.requirement[0] == '\0')
      {
        return false;
      }
      for (const char *c = refused.id; *c != '\0'; ++c)
      {
        if (*c < 'a' || *c > 'z')
          return false;
      }
      if (find_network_profile(refused.id) != nullptr)
        return false;
      WalletCatalogEntry entry = {};
      if (wallet_catalog_find(refused.id, &entry))
        return false;
      for (size_t other = index + 1; other < refused_chain_count(); ++other)
      {
        if (strcmp(kRefusedChains[other].id, refused.id) == 0)
          return false;
      }
    }
    char line[512] = {};
    if (!refused_chain_describe("beam", line, sizeof(line)) ||
        strstr(line, "slip44=1533") == nullptr ||
        strstr(line, "requires=") == nullptr)
    {
      return false;
    }
    char tiny[8] = {};
    if (refused_chain_describe("beam", tiny, sizeof(tiny)) || tiny[0] != '\0')
      return false;
    if (refused_chain_describe("btc", line, sizeof(line)))
      return false;
    if (refused_chain_describe(nullptr, line, sizeof(line)))
      return false;
    secure_zero(line, sizeof(line));
    return true;
  }
}

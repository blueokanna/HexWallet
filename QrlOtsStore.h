#ifndef HEXWALLET_QRL_OTS_STORE_H
#define HEXWALLET_QRL_OTS_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "QrlOtsJournal.h"
#include "QrlXmss.h"

namespace hexwallet
{
  class QrlOtsSlotPort
  {
  public:
    virtual ~QrlOtsSlotPort() = default;
    virtual bool read_slot(const uint8_t tag[kQrlOtsTagSize], uint8_t slot,
                           uint8_t *out, size_t size) = 0;
    virtual bool write_slot(const uint8_t tag[kQrlOtsTagSize], uint8_t slot,
                            const uint8_t *data, size_t size) = 0;
  };

  // Binds the journal protocol to one XMSS account.
  class QrlOtsAccount : public QrlOtsStorage
  {
  public:
    // The account tag is the first 128 bits of SHA-256(extended public key). It
    // names the slots, so two QRL accounts in one wallet never share a counter.
    QrlOtsAccount(QrlOtsSlotPort &port,
                  const uint8_t public_key[kQrlPublicKeySize]);
    QrlOtsAccount(const QrlOtsAccount &) = delete;
    QrlOtsAccount &operator=(const QrlOtsAccount &) = delete;

    bool read_slot(uint8_t slot, QrlOtsRecord *out) override;
    bool write_slot(uint8_t slot, const QrlOtsRecord &record) override;

    // Binds an unused account to index zero. Refuses when either slot already
    // holds a valid record, whatever tag it carries: a blank journal on a device
    // that still remembers the account would otherwise rewind the counter and
    // publish two signatures over the same one-time key.
    QrlOtsError bind();
    // First leaf this account may still sign with, or why it may not sign.
    QrlOtsError next_index(uint32_t *index);
    // Port consumed by qrl_xmss_sign_digest(). It re-reads the mark and advances
    // it through qrl_ots_reserve(), so a concurrent writer loses the race and
    // burns a leaf instead of reusing one.
    QrlOtsPort port();
    const uint8_t *tag() const { return tag_; }

  private:
    static bool port_read(void *context, const uint8_t key_id[32],
                          uint32_t *high_water);
    static bool port_reserve(void *context, const uint8_t key_id[32],
                             uint32_t expected, uint32_t next_high_water);

    QrlOtsSlotPort &port_;
    uint8_t tag_[kQrlOtsTagSize];
  };

  QrlOtsSlotPort *qrl_ots_platform_port();

  void qrl_ots_set_platform_port(QrlOtsSlotPort *port);

} // namespace hexwallet

#endif

#include "QrlOtsJournal.h"

#include <string.h>

namespace hexwallet
{

  namespace
  {

    constexpr uint8_t kQrlOtsMagic[4] = {'Q', 'O', 'T', '1'};
    static_assert(sizeof(QrlOtsRecord) == kQrlOtsRecordSize,
                  "the journal record must not carry padding");

    uint32_t crc32(const uint8_t *data, size_t size)
    {
      uint32_t crc = 0xFFFFFFFFU;
      for (size_t index = 0; index < size; ++index)
      {
        crc ^= data[index];
        for (uint8_t bit = 0; bit < 8; ++bit)
        {
          const uint32_t mask = 0U - (crc & 1U);
          crc = (crc >> 1) ^ (0xEDB88320U & mask);
        }
      }
      return ~crc;
    }

    bool record_valid(const QrlOtsRecord &record)
    {
      if (memcmp(record.magic, kQrlOtsMagic, sizeof(kQrlOtsMagic)) != 0)
        return false;
      const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&record);
      return crc32(bytes, kQrlOtsRecordSize - sizeof(uint32_t)) ==
             record.checksum;
    }

    QrlOtsRecord make_record(const uint8_t *tag, uint32_t index,
                             uint32_t sequence)
    {
      QrlOtsRecord record = {};
      memcpy(record.magic, kQrlOtsMagic, sizeof(kQrlOtsMagic));
      memcpy(record.tag, tag, kQrlOtsTagSize);
      record.index = index;
      record.sequence = sequence;
      const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&record);
      record.checksum = crc32(bytes, kQrlOtsRecordSize - sizeof(uint32_t));
      return record;
    }

    bool same_record(const QrlOtsRecord &left, const QrlOtsRecord &right)
    {
      return memcmp(&left, &right, sizeof(QrlOtsRecord)) == 0;
    }

    // Reads both slots. `newest` is only meaningful when `have_any` is set; the
    // short-circuit in the comparison below is what keeps index 2 unread before
    // the first valid record arrives.
    struct Journal
    {
      bool valid[kQrlOtsSlotCount];
      QrlOtsRecord record[kQrlOtsSlotCount];
      size_t newest;
      bool have_any;
      bool foreign;   // a valid record exists but for a different tag
    };

    Journal read_journal(QrlOtsStorage &storage, const uint8_t *tag)
    {
      Journal state = {};
      state.newest = kQrlOtsSlotCount;
      for (uint8_t slot = 0; slot < kQrlOtsSlotCount; ++slot)
      {
        QrlOtsRecord record = {};
        const bool valid =
            storage.read_slot(slot, &record) && record_valid(record);
        state.valid[slot] = valid;
        state.record[slot] = record;
        if (!valid)
          continue;
        if (memcmp(record.tag, tag, kQrlOtsTagSize) != 0)
        {
          state.foreign = true;
          continue;
        }
        if (!state.have_any ||
            record.index > state.record[state.newest].index ||
            (record.index == state.record[state.newest].index &&
             record.sequence > state.record[state.newest].sequence))
        {
          state.newest = slot;
          state.have_any = true;
        }
      }
      return state;
    }

    // Both slots receive the same record. That redundancy is what makes a
    // single corrupted slot harmless: whichever one survives proves the same
    // mark, so the counter can never regress and no leaf can be reused.
    //
    // A torn pair (slot 0 committed, slot 1 not) leaves the mark one higher
    // than the index the caller was told about, so the leaf in flight is
    // skipped instead of reused. The caller is told the reservation failed and
    // receives no index.
    QrlOtsError write_journal(QrlOtsStorage &storage,
                              const QrlOtsRecord &record)
    {
      for (uint8_t slot = 0; slot < kQrlOtsSlotCount; ++slot)
      {
        if (!storage.write_slot(slot, record))
          return QrlOtsError::StorageFailure;
        QrlOtsRecord readback = {};
        if (!storage.read_slot(slot, &readback) || !same_record(readback, record))
          return QrlOtsError::StorageFailure;
      }
      return QrlOtsError::Ok;
    }

  } // namespace

  QrlOtsError qrl_ots_high_water(QrlOtsStorage &storage,
                                 const uint8_t tag[kQrlOtsTagSize],
                                 uint32_t *out_index)
  {
    if (tag == nullptr || out_index == nullptr)
      return QrlOtsError::InvalidArgument;
    const Journal state = read_journal(storage, tag);
    if (!state.have_any)
      return state.foreign ? QrlOtsError::WrongAccount : QrlOtsError::Unknown;
    *out_index = state.record[state.newest].index;
    return QrlOtsError::Ok;
  }

  QrlOtsError qrl_ots_initialise(QrlOtsStorage &storage,
                                 const uint8_t tag[kQrlOtsTagSize])
  {
    if (tag == nullptr)
      return QrlOtsError::InvalidArgument;
    const Journal state = read_journal(storage, tag);
    // Any valid record, of any account, means this journal is in use.
    if (state.have_any)
      return QrlOtsError::StorageFailure;
    if (state.foreign)
      return QrlOtsError::WrongAccount;
    return write_journal(storage, make_record(tag, 0, 0));
  }

  QrlOtsError qrl_ots_reserve(QrlOtsStorage &storage,
                              const uint8_t tag[kQrlOtsTagSize],
                              uint32_t *out_index)
  {
    if (tag == nullptr || out_index == nullptr)
      return QrlOtsError::InvalidArgument;
    const Journal state = read_journal(storage, tag);
    if (!state.have_any)
      return state.foreign ? QrlOtsError::WrongAccount : QrlOtsError::Unknown;
    const QrlOtsRecord newest = state.record[state.newest];
    if (newest.index >= kQrlOtsLeaves)
      return QrlOtsError::Exhausted;
    const QrlOtsRecord next =
        make_record(tag, newest.index + 1U, newest.sequence + 1U);
    // Nothing is handed out until both durable copies prove themselves.
    if (write_journal(storage, next) != QrlOtsError::Ok)
      return QrlOtsError::StorageFailure;
    uint32_t high_water = 0;
    if (qrl_ots_high_water(storage, tag, &high_water) != QrlOtsError::Ok ||
        high_water != newest.index + 1U)
    {
      return QrlOtsError::StorageFailure;
    }
    *out_index = newest.index;
    return QrlOtsError::Ok;
  }

  const char *qrl_ots_error_text(QrlOtsError error)
  {
    switch (error)
    {
    case QrlOtsError::Ok:
      return "ok";
    case QrlOtsError::Unknown:
      return "one-time index state unknown";
    case QrlOtsError::Exhausted:
      return "xmss tree exhausted";
    case QrlOtsError::StorageFailure:
      return "reservation not durable";
    case QrlOtsError::WrongAccount:
      return "journal belongs to another account";
    case QrlOtsError::InvalidArgument:
      return "invalid argument";
    }
    return "unknown";
  }

  namespace
  {

    // Models the two failures that actually happen: a write that never reaches
    // flash, and a slot that is unreadable on the next boot.
    class FakeOtsStorage : public QrlOtsStorage
    {
    public:
      QrlOtsRecord slot[kQrlOtsSlotCount] = {};
      bool present[kQrlOtsSlotCount] = {false, false};
      int fail_write_slot = -1;

      bool read_slot(uint8_t index, QrlOtsRecord *out) override
      {
        if (index >= kQrlOtsSlotCount || out == nullptr || !present[index])
          return false;
        *out = slot[index];
        return true;
      }

      bool write_slot(uint8_t index, const QrlOtsRecord &record) override
      {
        if (index >= kQrlOtsSlotCount)
          return false;
        if (fail_write_slot == static_cast<int>(index))
          return false;
        slot[index] = record;
        present[index] = true;
        return true;
      }
    };

    const uint8_t kTagA[kQrlOtsTagSize] = {1, 2, 3, 4, 5, 6, 7, 8,
                                          9, 10, 11, 12, 13, 14, 15, 16};
    const uint8_t kTagB[kQrlOtsTagSize] = {16, 15, 14, 13, 12, 11, 10, 9,
                                          8, 7, 6, 5, 4, 3, 2, 1};

    bool reserve_is(FakeOtsStorage &storage, const uint8_t *tag,
                    uint32_t expected)
    {
      uint32_t index = 0xFFFFFFFFU;
      return qrl_ots_reserve(storage, tag, &index) == QrlOtsError::Ok &&
             index == expected;
    }

  } // namespace

  bool run_qrl_ots_self_tests()
  {
    bool passed = true;

    // A blank journal proves nothing; it must not be guessed at.
    {
      FakeOtsStorage storage;
      uint32_t index = 0;
      passed = passed &&
               qrl_ots_high_water(storage, kTagA, &index) ==
                   QrlOtsError::Unknown;
      passed = passed && qrl_ots_reserve(storage, kTagA, &index) ==
                             QrlOtsError::Unknown;
    }

    // Initialisation is a one-way door.
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok &&
               qrl_ots_initialise(storage, kTagA) ==
                   QrlOtsError::StorageFailure;
      uint32_t index = 99;
      passed = passed &&
               qrl_ots_high_water(storage, kTagA, &index) == QrlOtsError::Ok &&
               index == 0;
      // Another account may not adopt or reset this journal.
      passed = passed &&
               qrl_ots_initialise(storage, kTagB) == QrlOtsError::WrongAccount;
      passed = passed && qrl_ots_reserve(storage, kTagB, &index) ==
                             QrlOtsError::WrongAccount;
    }

    // Sequential reservations hand out each index exactly once.
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok;
      for (uint32_t expected = 0; expected < 8; ++expected)
        passed = passed && reserve_is(storage, kTagA, expected);
      uint32_t index = 0;
      passed = passed &&
               qrl_ots_high_water(storage, kTagA, &index) == QrlOtsError::Ok &&
               index == 8;
    }

    // A write that never lands hands out nothing and consumes nothing. The
    // reservation always targets the slot that is not the high-water mark, so
    // each state is failed on exactly the slot it would have written.
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok &&
               reserve_is(storage, kTagA, 0);
      uint32_t index = 77;
      storage.fail_write_slot = 0; // slot 1 now holds the mark, so 0 is targeted
      passed = passed && qrl_ots_reserve(storage, kTagA, &index) ==
                             QrlOtsError::StorageFailure;
      storage.fail_write_slot = -1;
      passed = passed && reserve_is(storage, kTagA, 1);
      // Now the mark lives in slot 0, so the next write goes to slot 1.
      storage.fail_write_slot = 1;
      passed = passed && qrl_ots_reserve(storage, kTagA, &index) ==
                             QrlOtsError::StorageFailure;
      storage.fail_write_slot = -1;
      passed = passed && reserve_is(storage, kTagA, 3);
    }

    // Power loss: each slot lost in turn must not move the mark backwards.
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok;
      for (uint32_t expected = 0; expected < 3; ++expected)
        passed = passed && reserve_is(storage, kTagA, expected);
      storage.present[1] = false;
      uint32_t index = 0;
      passed = passed &&
               qrl_ots_high_water(storage, kTagA, &index) == QrlOtsError::Ok &&
               index == 3;
      passed = passed && reserve_is(storage, kTagA, 3);
    }
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok;
      for (uint32_t expected = 0; expected < 4; ++expected)
        passed = passed && reserve_is(storage, kTagA, expected);
      storage.present[0] = false;
      uint32_t index = 0;
      passed = passed &&
               qrl_ots_high_water(storage, kTagA, &index) == QrlOtsError::Ok &&
               index == 4;
      passed = passed && reserve_is(storage, kTagA, 4);
    }
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok &&
               reserve_is(storage, kTagA, 0);
      storage.present[0] = false;
      storage.present[1] = false;
      uint32_t index = 0;
      passed = passed && qrl_ots_high_water(storage, kTagA, &index) ==
                             QrlOtsError::Unknown;
      passed = passed &&
               qrl_ots_reserve(storage, kTagA, &index) == QrlOtsError::Unknown;
      // With nothing left to compare against, re-initialising is the only way
      // back - which is exactly why the custody layer has to refuse this case
      // instead of calling it.
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok;
    }

    // A corrupted record counts as absent, and the survivor still protects the
    // leaves it knows about.
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok &&
               reserve_is(storage, kTagA, 0) && reserve_is(storage, kTagA, 1);
      // Two reservations left the mark at 2 in slot 0; corrupting slot 1 must
      // not disturb it.
      storage.slot[1].index ^= 0x01U;
      uint32_t index = 0;
      passed = passed &&
               qrl_ots_high_water(storage, kTagA, &index) == QrlOtsError::Ok &&
               index == 2;
      passed = passed && reserve_is(storage, kTagA, 2);
      storage.slot[0].checksum ^= 0xFFU;
      storage.slot[1].checksum ^= 0xFFU;
      passed = passed && qrl_ots_high_water(storage, kTagA, &index) ==
                             QrlOtsError::Unknown;
    }

    // Exhaustion: the last leaf goes out once, then the tree is done.
    {
      FakeOtsStorage storage;
      passed = passed && qrl_ots_initialise(storage, kTagA) == QrlOtsError::Ok;
      for (uint32_t step = 0; step + 1 < kQrlOtsLeaves; ++step)
      {
        uint32_t index = 0;
        if (qrl_ots_reserve(storage, kTagA, &index) != QrlOtsError::Ok ||
            index != step)
        {
          passed = false;
          break;
        }
      }
      passed = passed && reserve_is(storage, kTagA, kQrlOtsLeaves - 1);
      uint32_t index = 0;
      passed = passed &&
               qrl_ots_reserve(storage, kTagA, &index) == QrlOtsError::Exhausted;
      passed = passed &&
               qrl_ots_high_water(storage, kTagA, &index) == QrlOtsError::Ok &&
               index == kQrlOtsLeaves;
    }

    // Argument checks.
    {
      FakeOtsStorage storage;
      uint32_t index = 0;
      passed = passed && qrl_ots_reserve(storage, nullptr, &index) ==
                             QrlOtsError::InvalidArgument;
      passed = passed && qrl_ots_reserve(storage, kTagA, nullptr) ==
                             QrlOtsError::InvalidArgument;
      passed = passed && qrl_ots_initialise(storage, nullptr) ==
                             QrlOtsError::InvalidArgument;
    }
    return passed;
  }

} // namespace hexwallet

#include "QrCode.h"

#include <string.h>

namespace hexwallet
{
  namespace
  {

    // Total data capacity of the largest supported version, in codewords.
    constexpr size_t kMaxDataCodewords = 274;  // v10-L
    constexpr size_t kMaxTotalCodewords = 346; // v10-L data + EC
    constexpr size_t kMaxBitBufferBytes = kMaxDataCodewords + 8;

    struct VersionSpec
    {
      uint8_t version;
      uint8_t size;
      // Block layout: group 1 and group 2 block counts with their data codewords
      // per block, then the EC codewords every block carries.
      uint8_t blocks_g1;
      uint8_t data_g1;
      uint8_t blocks_g2;
      uint8_t data_g2;
      uint8_t ec_per_block;
      uint8_t ecc_bits; // format-information value for the level
      uint16_t total_codewords;
    };

    // Versions 1-10, levels L, M, Q and H. data + blocks * ec must equal
    // total_codewords for every row; the self-test checks that invariant and the
    // host cross-check compares every produced matrix with a reference encoder, so a
    // mistyped row cannot survive.
    constexpr VersionSpec kSpecs[] = {
        {1, 21, 1, 19, 0, 0, 7, 0x01, 26},     // v1-L
        {1, 21, 1, 16, 0, 0, 10, 0x00, 26},    // v1-M
        {1, 21, 1, 13, 0, 0, 13, 0x03, 26},    // v1-Q
        {1, 21, 1, 9, 0, 0, 17, 0x02, 26},     // v1-H
        {2, 25, 1, 34, 0, 0, 10, 0x01, 44},    // v2-L
        {2, 25, 1, 28, 0, 0, 16, 0x00, 44},    // v2-M
        {2, 25, 1, 22, 0, 0, 22, 0x03, 44},    // v2-Q
        {2, 25, 1, 16, 0, 0, 28, 0x02, 44},    // v2-H
        {3, 29, 1, 55, 0, 0, 15, 0x01, 70},    // v3-L
        {3, 29, 1, 44, 0, 0, 26, 0x00, 70},    // v3-M
        {3, 29, 2, 17, 0, 0, 18, 0x03, 70},    // v3-Q
        {3, 29, 2, 13, 0, 0, 22, 0x02, 70},    // v3-H
        {4, 33, 1, 80, 0, 0, 20, 0x01, 100},   // v4-L
        {4, 33, 2, 32, 0, 0, 18, 0x00, 100},   // v4-M
        {4, 33, 2, 24, 0, 0, 26, 0x03, 100},   // v4-Q
        {4, 33, 4, 9, 0, 0, 16, 0x02, 100},    // v4-H
        {5, 37, 1, 108, 0, 0, 26, 0x01, 134},  // v5-L
        {5, 37, 2, 43, 0, 0, 24, 0x00, 134},   // v5-M
        {5, 37, 2, 15, 2, 16, 18, 0x03, 134},  // v5-Q
        {5, 37, 2, 11, 2, 12, 22, 0x02, 134},  // v5-H
        {6, 41, 2, 68, 0, 0, 18, 0x01, 172},   // v6-L
        {6, 41, 4, 27, 0, 0, 16, 0x00, 172},   // v6-M
        {6, 41, 4, 19, 0, 0, 24, 0x03, 172},   // v6-Q
        {6, 41, 4, 15, 0, 0, 28, 0x02, 172},   // v6-H
        {7, 45, 2, 78, 0, 0, 20, 0x01, 196},   // v7-L
        {7, 45, 4, 31, 0, 0, 18, 0x00, 196},   // v7-M
        {7, 45, 2, 14, 4, 15, 18, 0x03, 196},  // v7-Q
        {7, 45, 4, 13, 1, 14, 26, 0x02, 196},  // v7-H
        {8, 49, 2, 97, 0, 0, 24, 0x01, 242},   // v8-L
        {8, 49, 2, 38, 2, 39, 22, 0x00, 242},  // v8-M
        {8, 49, 4, 18, 2, 19, 22, 0x03, 242},  // v8-Q
        {8, 49, 4, 14, 2, 15, 26, 0x02, 242},  // v8-H
        {9, 53, 2, 116, 0, 0, 30, 0x01, 292},  // v9-L
        {9, 53, 3, 36, 2, 37, 22, 0x00, 292},  // v9-M
        {9, 53, 4, 16, 4, 17, 20, 0x03, 292},  // v9-Q
        {9, 53, 4, 12, 4, 13, 24, 0x02, 292},  // v9-H
        {10, 57, 2, 68, 2, 69, 18, 0x01, 346}, // v10-L
        {10, 57, 4, 43, 1, 44, 26, 0x00, 346}, // v10-M
        {10, 57, 6, 19, 2, 20, 24, 0x03, 346}, // v10-Q
        {10, 57, 6, 15, 2, 16, 28, 0x02, 346}, // v10-H
    };

    constexpr uint8_t kMaxBlocks = 8;
    constexpr size_t kMaxEcPerBlock = 30;

    uint8_t ecc_field(QrEcc ecc)
    {
      switch (ecc)
      {
      case QrEcc::Low:
        return 0x01;
      case QrEcc::Medium:
        return 0x00;
      case QrEcc::Quartile:
        return 0x03;
      case QrEcc::High:
        return 0x02;
      }
      return 0xFF;
    }

    const VersionSpec *find_spec(uint8_t version, QrEcc ecc)
    {
      for (const VersionSpec &spec : kSpecs)
      {
        if (spec.version == version && spec.ecc_bits == ecc_field(ecc))
        {
          return &spec;
        }
      }
      return nullptr;
    }

    size_t total_data_codewords(const VersionSpec &spec)
    {
      return static_cast<size_t>(spec.blocks_g1) * spec.data_g1 +
             static_cast<size_t>(spec.blocks_g2) * spec.data_g2;
    }

    size_t total_blocks(const VersionSpec &spec)
    {
      return static_cast<size_t>(spec.blocks_g1) + spec.blocks_g2;
    }

    // Alignment pattern centres by version (ISO/IEC 18004 Annex E).
    uint8_t alignment_centres(uint8_t version, uint8_t centres[3])
    {
      switch (version)
      {
      case 1:
        return 0;
      case 2:
        centres[0] = 6;
        centres[1] = 18;
        return 2;
      case 3:
        centres[0] = 6;
        centres[1] = 22;
        return 2;
      case 4:
        centres[0] = 6;
        centres[1] = 26;
        return 2;
      case 5:
        centres[0] = 6;
        centres[1] = 30;
        return 2;
      case 6:
        centres[0] = 6;
        centres[1] = 34;
        return 2;
      case 7:
        centres[0] = 6;
        centres[1] = 22;
        centres[2] = 38;
        return 3;
      case 8:
        centres[0] = 6;
        centres[1] = 24;
        centres[2] = 42;
        return 3;
      case 9:
        centres[0] = 6;
        centres[1] = 26;
        centres[2] = 46;
        return 3;
      case 10:
        centres[0] = 6;
        centres[1] = 28;
        centres[2] = 50;
        return 3;
      default:
        return 0;
      }
    }

    // ---- GF(256) with the QR primitive polynomial 0x11D ------------------------

    uint8_t gf_mul(uint8_t a, uint8_t b)
    {
      uint16_t product = 0;
      for (int bit = 0; bit < 8; ++bit)
      {
        if ((b & 0x01U) != 0)
          product ^= a;
        const bool carry = (a & 0x80U) != 0;
        a = static_cast<uint8_t>(a << 1);
        if (carry)
          a ^= 0x1DU;
        b = static_cast<uint8_t>(b >> 1);
      }
      return static_cast<uint8_t>(product);
    }

    void rs_generator(uint8_t degree, uint8_t *polynomial)
    {
      // polynomial[0] is the highest-order coefficient (1); the array holds degree+1
      // entries.
      memset(polynomial, 0, static_cast<size_t>(degree) + 1);
      polynomial[0] = 1;
      uint8_t root = 1;
      for (uint8_t term = 0; term < degree; ++term)
      {
        for (int index = degree; index > 0; --index)
        {
          polynomial[index] = static_cast<uint8_t>(
              polynomial[index] ^ gf_mul(polynomial[index - 1], root));
        }
        root = gf_mul(root, 2);
      }
    }

    void rs_remainder(const uint8_t *data, size_t data_size, uint8_t ec_size,
                      uint8_t *out)
    {
      uint8_t generator[kMaxEcPerBlock + 1];
      rs_generator(ec_size, generator);
      uint8_t remainder[kMaxEcPerBlock];
      memset(remainder, 0, sizeof(remainder));
      for (size_t index = 0; index < data_size; ++index)
      {
        const uint8_t factor = static_cast<uint8_t>(data[index] ^ remainder[0]);
        memmove(remainder, remainder + 1, static_cast<size_t>(ec_size) - 1);
        remainder[ec_size - 1] = 0;
        for (uint8_t term = 0; term < ec_size; ++term)
        {
          remainder[term] = static_cast<uint8_t>(
              remainder[term] ^ gf_mul(generator[term + 1], factor));
        }
      }
      memcpy(out, remainder, ec_size);
    }

    // ---- Bit buffer -----------------------------------------------------------

    struct BitBuffer
    {
      uint8_t bytes[kMaxBitBufferBytes];
      size_t bits;
    };

    void put_bits(BitBuffer *buffer, uint32_t value, uint8_t count)
    {
      for (int bit = count - 1; bit >= 0; --bit)
      {
        const uint8_t set = (value >> bit) & 1U;
        const size_t index = buffer->bits / 8;
        const uint8_t mask = static_cast<uint8_t>(0x80U >> (buffer->bits % 8));
        if (set != 0)
          buffer->bytes[index] |= mask;
        ++buffer->bits;
      }
    }

    // ---- Matrix helpers -------------------------------------------------------

    bool in_finder(uint8_t row, uint8_t column, uint8_t size)
    {
      const bool top_left = row < 9 && column < 9;
      const bool top_right = row < 9 && column >= static_cast<uint8_t>(size - 8);
      const bool bottom_left = row >= static_cast<uint8_t>(size - 8) && column < 9;
      return top_left || top_right || bottom_left;
    }

    bool in_timing(uint8_t row, uint8_t column)
    {
      return row == 6 || column == 6;
    }

    // Version information only exists from version 7: two 3x6 blocks next to the
    // finder patterns. They are function modules, so data must never be placed
    // there.
    bool in_version_info(uint8_t row, uint8_t column, uint8_t version,
                         uint8_t size)
    {
      if (version < 7)
        return false;
      const uint8_t start = static_cast<uint8_t>(size - 11);
      const bool top_right = row < 6 && column >= start && column < static_cast<uint8_t>(start + 3);
      const bool bottom_left = column < 6 && row >= start && row < static_cast<uint8_t>(start + 3);
      return top_right || bottom_left;
    }

    bool in_alignment(uint8_t row, uint8_t column, uint8_t version, uint8_t size)
    {
      uint8_t centres[3];
      const uint8_t count = alignment_centres(version, centres);
      for (uint8_t a = 0; a < count; ++a)
      {
        for (uint8_t b = 0; b < count; ++b)
        {
          // Same exclusion as the drawing pass: a centre that overlaps a finder
          // pattern has no alignment pattern, so its 5x5 area must stay data.
          if (in_finder(centres[a], centres[b], size))
            continue;
          const int dr = static_cast<int>(row) - centres[a];
          const int dc = static_cast<int>(column) - centres[b];
          if (dr >= -2 && dr <= 2 && dc >= -2 && dc <= 2)
            return true;
        }
      }
      return false;
    }

    // Function modules (finder, separators, timing, alignment, version information,
    // format, dark module) are written before data and never overwritten by it.
    bool is_function_module(uint8_t row, uint8_t column, uint8_t version,
                            uint8_t size)
    {
      if (row == 8 && column == static_cast<uint8_t>(size - 8))
        return true;
      if (in_finder(row, column, size))
        return true;
      if (in_timing(row, column))
        return true;
      if (in_alignment(row, column, version, size))
        return true;
      if (in_version_info(row, column, version, size))
        return true;
      return false;
    }

    void set_module(QrCode *code, uint8_t row, uint8_t column, bool dark)
    {
      code->modules[static_cast<size_t>(row) * code->size + column] = dark ? 1 : 0;
    }

    bool get_module(const QrCode &code, uint8_t row, uint8_t column)
    {
      return code.modules[static_cast<size_t>(row) * code.size + column] != 0;
    }

    void draw_finder(QrCode *code, uint8_t top, uint8_t left)
    {
      for (int dr = -1; dr <= 7; ++dr)
      {
        for (int dc = -1; dc <= 7; ++dc)
        {
          const int row = top + dr;
          const int column = left + dc;
          if (row < 0 || column < 0 || row >= code->size || column >= code->size)
          {
            continue;
          }
          const bool inside = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
          const bool ring = inside && (dr == 0 || dr == 6 || dc == 0 || dc == 6);
          const bool core = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
          set_module(code, static_cast<uint8_t>(row), static_cast<uint8_t>(column),
                     ring || core);
        }
      }
    }

    void draw_alignment(QrCode *code, uint8_t version)
    {
      uint8_t centres[3];
      const uint8_t count = alignment_centres(version, centres);
      for (uint8_t a = 0; a < count; ++a)
      {
        for (uint8_t b = 0; b < count; ++b)
        {
          const uint8_t row = centres[a];
          const uint8_t column = centres[b];
          if (in_finder(row, column, code->size))
            continue;
          for (int dr = -2; dr <= 2; ++dr)
          {
            for (int dc = -2; dc <= 2; ++dc)
            {
              const bool dark = dr == -2 || dr == 2 || dc == -2 || dc == 2 ||
                                (dr == 0 && dc == 0);
              set_module(code, static_cast<uint8_t>(row + dr),
                         static_cast<uint8_t>(column + dc), dark);
            }
          }
        }
      }
    }

    // 18-bit version information: 6 data bits followed by a BCH(18, 6) remainder
    // modulo x^12 + x^11 + x^10 + x^9 + x^8 + x^5 + x^2 + 1 (0x1F25).
    uint32_t version_info_bits(uint8_t version)
    {
      uint32_t value = static_cast<uint32_t>(version) << 12;
      for (int bit = 17; bit >= 12; --bit)
      {
        if ((value & (1UL << bit)) != 0)
          value ^= 0x1F25UL << (bit - 12);
      }
      return (static_cast<uint32_t>(version) << 12) | value;
    }

    void draw_version_info(QrCode *code)
    {
      if (code->version < 7)
        return;
      const uint32_t bits = version_info_bits(code->version);
      const uint8_t size = code->size;
      const uint8_t start = static_cast<uint8_t>(size - 11);
      for (uint8_t index = 0; index < 18; ++index)
      {
        const bool dark = ((bits >> index) & 1U) != 0;
        const uint8_t row = static_cast<uint8_t>(start + (index % 3));
        const uint8_t column = static_cast<uint8_t>(index / 3);
        set_module(code, row, column, dark); // bottom-left block
        set_module(code, column, row, dark); // top-right block
      }
    }

    uint16_t format_bits(uint8_t ecc_bits, uint8_t mask)
    {
      const uint16_t data = static_cast<uint16_t>((ecc_bits << 3) | mask);
      uint16_t value = static_cast<uint16_t>(data << 10);
      for (int bit = 14; bit >= 10; --bit)
      {
        if ((value & (1U << bit)) != 0)
          value ^= static_cast<uint16_t>(0x537U << (bit - 10));
      }
      return static_cast<uint16_t>(((data << 10) | value) ^ 0x5412U);
    }

    void draw_format(QrCode *code, uint16_t bits)
    {
      const uint8_t size = code->size;
      for (uint8_t index = 0; index <= 5; ++index)
      {
        set_module(code, index, 8, ((bits >> index) & 1U) != 0);
      }
      set_module(code, 7, 8, ((bits >> 6) & 1U) != 0);
      set_module(code, 8, 8, ((bits >> 7) & 1U) != 0);
      set_module(code, 8, 7, ((bits >> 8) & 1U) != 0);
      for (uint8_t index = 9; index < 15; ++index)
      {
        set_module(code, 8, static_cast<uint8_t>(14 - index),
                   ((bits >> index) & 1U) != 0);
      }
      // Second copy: bits 0-7 along row 8 from the right edge inwards, bits 8-14
      // down column 8 from (size-7) to the bottom.
      for (uint8_t index = 0; index < 8; ++index)
      {
        set_module(code, 8, static_cast<uint8_t>(size - 1 - index),
                   ((bits >> index) & 1U) != 0);
      }
      for (uint8_t index = 8; index < 15; ++index)
      {
        set_module(code, static_cast<uint8_t>(size - 15 + index), 8,
                   ((bits >> index) & 1U) != 0);
      }
      // The dark module is always set.
      set_module(code, static_cast<uint8_t>(size - 8), 8, true);
    }

    bool mask_applies(uint8_t mask, uint8_t row, uint8_t column)
    {
      switch (mask)
      {
      case 0:
        return ((row + column) % 2) == 0;
      case 1:
        return (row % 2) == 0;
      case 2:
        return (column % 3) == 0;
      case 3:
        return ((row + column) % 3) == 0;
      case 4:
        return (((row / 2) + (column / 3)) % 2) == 0;
      case 5:
        return (((row * column) % 2) + ((row * column) % 3)) == 0;
      case 6:
        return ((((row * column) % 2) + ((row * column) % 3)) % 2) == 0;
      case 7:
        return ((((row + column) % 2) + ((row * column) % 3)) % 2) == 0;
      default:
        return false;
      }
    }

    // Zigzag placement: two-module-wide columns from the right, skipping column 6.
    // Modules left over after the last codeword bit are remainder bits and stay 0,
    // which is what the standard requires.
    uint16_t place_data(QrCode *code, const uint8_t *codewords, size_t count,
                        uint8_t mask)
    {
      uint16_t placed = 0;
      const uint8_t size = code->size;
      const size_t total_bits = count * 8;
      bool upward = true;
      int column = size - 1;
      while (column > 0)
      {
        if (column == 6)
          --column;
        for (uint8_t step = 0; step < size; ++step)
        {
          const uint8_t row = upward ? static_cast<uint8_t>(size - 1 - step) : step;
          for (uint8_t offset = 0; offset < 2; ++offset)
          {
            const uint8_t target = static_cast<uint8_t>(column - offset);
            if (is_function_module(row, target, code->version, size))
              continue;
            bool dark = false;
            if (placed < total_bits)
            {
              const size_t byte_index = placed / 8;
              const uint8_t bit = static_cast<uint8_t>(0x80U >> (placed % 8));
              dark = (codewords[byte_index] & bit) != 0;
              ++placed;
            }
            if (mask_applies(mask, row, target))
              dark = !dark;
            set_module(code, row, target, dark);
          }
        }
        upward = !upward;
        column -= 2;
      }
      return placed;
    }

    uint16_t penalty(const QrCode &code)
    {
      uint16_t total = 0;
      const uint8_t size = code.size;
      for (uint8_t row = 0; row < size; ++row)
      {
        int run = 1;
        for (uint8_t column = 1; column < size; ++column)
        {
          if (get_module(code, row, column) == get_module(code, row, column - 1))
          {
            ++run;
          }
          else
          {
            if (run >= 5)
              total = static_cast<uint16_t>(total + run - 2);
            run = 1;
          }
        }
        if (run >= 5)
          total = static_cast<uint16_t>(total + run - 2);
      }
      for (uint8_t column = 0; column < size; ++column)
      {
        int run = 1;
        for (uint8_t row = 1; row < size; ++row)
        {
          if (get_module(code, row, column) == get_module(code, row - 1, column))
          {
            ++run;
          }
          else
          {
            if (run >= 5)
              total = static_cast<uint16_t>(total + run - 2);
            run = 1;
          }
        }
        if (run >= 5)
          total = static_cast<uint16_t>(total + run - 2);
      }
      for (uint8_t row = 0; row + 1 < size; ++row)
      {
        for (uint8_t column = 0; column + 1 < size; ++column)
        {
          const bool value = get_module(code, row, column);
          if (value == get_module(code, row, column + 1) &&
              value == get_module(code, row + 1, column) &&
              value == get_module(code, row + 1, column + 1))
          {
            total = static_cast<uint16_t>(total + 3);
          }
        }
      }
      // Finder-like 1:1:3:1:1 patterns in rows and columns.
      for (uint8_t row = 0; row < size; ++row)
      {
        for (uint8_t column = 0; column + 6 < size; ++column)
        {
          if (get_module(code, row, column) && !get_module(code, row, column + 1) &&
              get_module(code, row, column + 2) && get_module(code, row, column + 3) &&
              get_module(code, row, column + 4) && !get_module(code, row, column + 5) &&
              get_module(code, row, column + 6))
          {
            total = static_cast<uint16_t>(total + 40);
          }
        }
      }
      for (uint8_t column = 0; column < size; ++column)
      {
        for (uint8_t row = 0; row + 6 < size; ++row)
        {
          if (get_module(code, row, column) && !get_module(code, row + 1, column) &&
              get_module(code, row + 2, column) && get_module(code, row + 3, column) &&
              get_module(code, row + 4, column) && !get_module(code, row + 5, column) &&
              get_module(code, row + 6, column))
          {
            total = static_cast<uint16_t>(total + 40);
          }
        }
      }
      return total;
    } // Splits the data codewords into the version's blocks, appends each block's EC
    // codewords and interleaves both halves the way the standard prescribes.
    bool build_codewords(const VersionSpec &spec, const uint8_t *data,
                         uint8_t *out)
    {
      if (spec.blocks_g1 + spec.blocks_g2 > kMaxBlocks)
        return false;
      const uint8_t *block_data[kMaxBlocks];
      uint8_t block_size[kMaxBlocks];
      uint8_t block_ec[kMaxBlocks][kMaxEcPerBlock];
      size_t offset = 0;
      size_t block = 0;
      for (uint8_t group = 0; group < 2; ++group)
      {
        const uint8_t count = group == 0 ? spec.blocks_g1 : spec.blocks_g2;
        const uint8_t size = group == 0 ? spec.data_g1 : spec.data_g2;
        for (uint8_t index = 0; index < count; ++index)
        {
          block_data[block] = data + offset;
          block_size[block] = size;
          rs_remainder(block_data[block], size, spec.ec_per_block, block_ec[block]);
          offset += size;
          ++block;
        }
      }
      if (offset != total_data_codewords(spec))
        return false;

      size_t position = 0;
      size_t widest = 0;
      for (size_t index = 0; index < block; ++index)
      {
        if (block_size[index] > widest)
          widest = block_size[index];
      }
      for (size_t column = 0; column < widest; ++column)
      {
        for (size_t index = 0; index < block; ++index)
        {
          if (column < block_size[index])
            out[position++] = block_data[index][column];
        }
      }
      for (uint8_t column = 0; column < spec.ec_per_block; ++column)
      {
        for (size_t index = 0; index < block; ++index)
        {
          out[position++] = block_ec[index][column];
        }
      }
      return position == spec.total_codewords;
    }

    void draw_symbol(QrCode *code, const VersionSpec &spec, const uint8_t *codewords,
                     uint8_t mask)
    {
      code->version = spec.version;
      code->size = spec.size;
      code->mask = mask;
      draw_finder(code, 0, 0);
      draw_finder(code, 0, static_cast<uint8_t>(code->size - 7));
      draw_finder(code, static_cast<uint8_t>(code->size - 7), 0);
      for (uint8_t index = 8; index + 8 < code->size; ++index)
      {
        const bool dark = (index % 2) == 0;
        set_module(code, 6, index, dark);
        set_module(code, index, 6, dark);
      }
      draw_alignment(code, code->version);
      draw_version_info(code);
      place_data(code, codewords, spec.total_codewords, mask);
      draw_format(code, format_bits(spec.ecc_bits, mask));
    }

  } // namespace

  size_t qr_capacity(uint8_t version, QrEcc ecc)
  {
    const VersionSpec *spec = find_spec(version, ecc);
    if (spec == nullptr)
      return 0;
    const size_t data_bits = total_data_codewords(*spec) * 8;
    const size_t header_bits = version < 10 ? 12 : 20;
    if (data_bits <= header_bits)
      return 0;
    return (data_bits - header_bits) / 8;
  }

  bool qr_encode_masked(const uint8_t *payload, size_t size, QrEcc ecc,
                        uint8_t mask, QrCode *out)
  {
    if (payload == nullptr || size == 0 || out == nullptr || mask > 7)
      return false;

    const VersionSpec *spec = nullptr;
    for (const VersionSpec &candidate : kSpecs)
    {
      if (candidate.ecc_bits != ecc_field(ecc))
        continue;
      if (qr_capacity(candidate.version, ecc) >= size)
      {
        spec = &candidate;
        break;
      }
    }
    if (spec == nullptr)
      return false;

    const size_t data_codewords = total_data_codewords(*spec);
    BitBuffer stream = {};
    put_bits(&stream, 0x4, 4);
    put_bits(&stream, static_cast<uint32_t>(size), spec->version < 10 ? 8 : 16);
    for (size_t index = 0; index < size; ++index)
    {
      put_bits(&stream, payload[index], 8);
    }
    const size_t capacity_bits = data_codewords * 8;
    if (stream.bits > capacity_bits)
      return false;
    const size_t remaining = capacity_bits - stream.bits;
    put_bits(&stream, 0, static_cast<uint8_t>(remaining < 4 ? remaining : 4));
    while ((stream.bits % 8) != 0)
      put_bits(&stream, 0, 1);
    uint8_t pad = 0xEC;
    while ((stream.bits / 8) < data_codewords)
    {
      put_bits(&stream, pad, 8);
      pad = pad == 0xEC ? 0x11 : 0xEC;
    }

    uint8_t codewords[kMaxTotalCodewords];
    if (!build_codewords(*spec, stream.bytes, codewords))
      return false;

    memset(out->modules, 0, sizeof(out->modules));
    out->ecc = ecc;
    draw_symbol(out, *spec, codewords, mask);
    return true;
  }

  bool qr_encode(const uint8_t *payload, size_t size, QrEcc ecc, QrCode *out)
  {
    if (out == nullptr)
      return false;
    QrCode best = {};
    bool have_best = false;
    uint16_t best_penalty = 0xFFFF;
    for (uint8_t mask = 0; mask < 8; ++mask)
    {
      QrCode candidate = {};
      if (!qr_encode_masked(payload, size, ecc, mask, &candidate))
        return false;
      const uint16_t score = penalty(candidate);
      if (!have_best || score < best_penalty)
      {
        best = candidate;
        best_penalty = score;
        have_best = true;
      }
    }
    if (!have_best)
      return false;
    *out = best;
    return true;
  }

  const char *qr_ecc_name(QrEcc ecc)
  {
    switch (ecc)
    {
    case QrEcc::High:
      return "H";
    case QrEcc::Quartile:
      return "Q";
    case QrEcc::Medium:
      return "M";
    case QrEcc::Low:
      return "L";
    }
    return "?";
  }

  bool qr_encode_best(const uint8_t *payload, size_t size, QrCode *out,
                      QrEcc *chosen)
  {
    if (payload == nullptr || size == 0 || out == nullptr)
      return false;
    static const QrEcc kFallback[] = {QrEcc::High, QrEcc::Quartile, QrEcc::Medium};
    for (QrEcc level : kFallback)
    {
      if (size > qr_capacity(kQrMaxVersion, level))
        continue;
      if (!qr_encode(payload, size, level, out))
        continue;
      if (chosen != nullptr)
        *chosen = level;
      return true;
    }
    // Below M there is no fallback: a symbol that survives one scratch is not a
    // wallet address.
    return false;
  }

  bool qr_render(const QrCode &code, uint8_t *bitmap, size_t bitmap_size,
                 uint16_t panel_width, uint16_t panel_height, uint16_t x,
                 uint16_t y, uint8_t scale)
  {
    if (bitmap == nullptr || code.size == 0 || scale == 0)
      return false;
    if (bitmap_size < eink_frame_bytes(panel_width, panel_height))
      return false;
    const size_t stride = eink_row_bytes(panel_width);
    bool fitted = true;
    for (uint8_t row = 0; row < code.size; ++row)
    {
      for (uint8_t column = 0; column < code.size; ++column)
      {
        if (code.modules[static_cast<size_t>(row) * code.size + column] == 0)
        {
          continue;
        }
        for (uint8_t dy = 0; dy < scale; ++dy)
        {
          const uint32_t py = static_cast<uint32_t>(y) + row * scale + dy;
          if (py >= panel_height)
          {
            fitted = false;
            continue;
          }
          for (uint8_t dx = 0; dx < scale; ++dx)
          {
            const uint32_t px = static_cast<uint32_t>(x) + column * scale + dx;
            if (px >= panel_width)
            {
              fitted = false;
              continue;
            }
            bitmap[static_cast<size_t>(py) * stride + (px / 8)] |=
                static_cast<uint8_t>(0x80U >> (px % 8));
          }
        }
      }
    }
    return fitted;
  }

  namespace
  {

    // Minimal reader used only by the self-test. It re-derives the layout instead of
    // reusing encoder state, so a wrong zigzag, mask, block split or interleave
    // shows up as a syndrome that is not zero.
    bool decode_check(const QrCode &code, const uint8_t *payload, size_t size)
    {
      const VersionSpec *spec = find_spec(code.version, code.ecc);
      if (spec == nullptr)
        return false;
      // Both format copies must agree with the encoder's own output.
      uint16_t first = 0;
      for (uint8_t index = 0; index <= 5; ++index)
      {
        if (get_module(code, index, 8))
          first = static_cast<uint16_t>(first | (1U << index));
      }
      if (get_module(code, 7, 8))
        first |= 1U << 6;
      if (get_module(code, 8, 8))
        first |= 1U << 7;
      if (get_module(code, 8, 7))
        first |= 1U << 8;
      for (uint8_t index = 9; index < 15; ++index)
      {
        if (get_module(code, 8, static_cast<uint8_t>(14 - index)))
        {
          first = static_cast<uint16_t>(first | (1U << index));
        }
      }
      uint16_t second = 0;
      for (uint8_t index = 0; index < 8; ++index)
      {
        if (get_module(code, 8, static_cast<uint8_t>(code.size - 1 - index)))
        {
          second = static_cast<uint16_t>(second | (1U << index));
        }
      }
      for (uint8_t index = 8; index < 15; ++index)
      {
        if (get_module(code, static_cast<uint8_t>(code.size - 15 + index), 8))
        {
          second = static_cast<uint16_t>(second | (1U << index));
        }
      }
      const uint16_t expected_format = format_bits(spec->ecc_bits, code.mask);
      if (first != expected_format || second != expected_format)
        return false;

      // Version information must decode back to the version it was built for.
      if (code.version >= 7)
      {
        const uint32_t expected_version = version_info_bits(code.version);
        uint32_t read = 0;
        const uint8_t start = static_cast<uint8_t>(code.size - 11);
        for (uint8_t index = 0; index < 18; ++index)
        {
          const uint8_t row = static_cast<uint8_t>(start + (index % 3));
          const uint8_t column = static_cast<uint8_t>(index / 3);
          const bool bottom_left = get_module(code, row, column);
          const bool top_right = get_module(code, column, row);
          if (bottom_left != top_right)
            return false;
          if (bottom_left)
            read |= 1UL << index;
        }
        if (read != expected_version)
          return false;
      }

      // Read the data modules back through the same zigzag and unmask.
      const size_t total_bits = static_cast<size_t>(spec->total_codewords) * 8;
      uint8_t stream[kMaxTotalCodewords];
      memset(stream, 0, sizeof(stream));
      size_t read = 0;
      bool upward = true;
      int column = code.size - 1;
      while (column > 0)
      {
        if (column == 6)
          --column;
        for (uint8_t step = 0; step < code.size; ++step)
        {
          const uint8_t row = upward ? static_cast<uint8_t>(code.size - 1 - step) : step;
          for (uint8_t offset = 0; offset < 2; ++offset)
          {
            const uint8_t target = static_cast<uint8_t>(column - offset);
            if (is_function_module(row, target, code.version, code.size))
              continue;
            if (read >= total_bits)
              continue;
            bool dark = get_module(code, row, target);
            if (mask_applies(code.mask, row, target))
              dark = !dark;
            if (dark)
              stream[read / 8] = static_cast<uint8_t>(stream[read / 8] | (0x80U >> (read % 8)));
            ++read;
          }
        }
        upward = !upward;
        column -= 2;
      }
      if (read < total_bits)
        return false;

      // De-interleave into per-block data + EC and require zero syndromes.
      uint8_t block_data[kMaxBlocks][kMaxDataCodewords];
      uint8_t block_ec[kMaxBlocks][kMaxEcPerBlock];
      uint8_t block_size[kMaxBlocks];
      size_t block = 0;
      for (uint8_t group = 0; group < 2; ++group)
      {
        const uint8_t count = group == 0 ? spec->blocks_g1 : spec->blocks_g2;
        const uint8_t width = group == 0 ? spec->data_g1 : spec->data_g2;
        for (uint8_t index = 0; index < count; ++index)
        {
          block_size[block] = width;
          ++block;
        }
      }
      size_t widest = 0;
      for (size_t index = 0; index < block; ++index)
      {
        if (block_size[index] > widest)
          widest = block_size[index];
      }
      size_t position = 0;
      for (size_t col = 0; col < widest; ++col)
      {
        for (size_t index = 0; index < block; ++index)
        {
          if (col < block_size[index])
            block_data[index][col] = stream[position++];
        }
      }
      for (uint8_t col = 0; col < spec->ec_per_block; ++col)
      {
        for (size_t index = 0; index < block; ++index)
        {
          block_ec[index][col] = stream[position++];
        }
      }
      if (position != spec->total_codewords)
        return false;

      for (size_t index = 0; index < block; ++index)
      {
        for (uint8_t root_index = 0; root_index < spec->ec_per_block; ++root_index)
        {
          uint8_t root = 1;
          for (uint8_t power = 0; power < root_index; ++power)
            root = gf_mul(root, 2);
          uint8_t syndrome = 0;
          for (size_t cw = 0; cw < block_size[index]; ++cw)
          {
            syndrome = static_cast<uint8_t>(gf_mul(syndrome, root) ^ block_data[index][cw]);
          }
          for (uint8_t cw = 0; cw < spec->ec_per_block; ++cw)
          {
            syndrome = static_cast<uint8_t>(gf_mul(syndrome, root) ^ block_ec[index][cw]);
          }
          if (syndrome != 0)
            return false;
        }
      }

      // Byte-mode header and payload round-trip through the de-interleaved data
      // codewords, in block order: a payload can span blocks, so reading only the
      // first block would fail for every multi-block version.
      uint8_t head[kMaxDataCodewords];
      size_t head_size = 0;
      for (size_t index = 0; index < block; ++index)
      {
        memcpy(head + head_size, block_data[index], block_size[index]);
        head_size += block_size[index];
      }
      if (head_size != total_data_codewords(*spec))
        return false;
      if ((head[0] >> 4) != 0x04)
        return false;
      const size_t count_bits = code.version < 10 ? 8 : 16;
      size_t length = 0;
      size_t bit = 4;
      for (size_t index = 0; index < count_bits; ++index)
      {
        const size_t source = bit + index;
        length = (length << 1) | ((head[source / 8] >> (7 - (source % 8))) & 1U);
      }
      if (length != size)
        return false;
      bit += count_bits;
      for (size_t index = 0; index < size; ++index)
      {
        uint8_t value = 0;
        for (uint8_t offset = 0; offset < 8; ++offset)
        {
          const size_t source = bit + index * 8 + offset;
          value = static_cast<uint8_t>((value << 1) | ((head[source / 8] >> (7 - (source % 8))) & 1U));
        }
        if (value != payload[index])
          return false;
      }
      return true;
    }

  } // namespace

  bool run_qr_code_self_tests()
  {
    bool passed = true;

    // Every spec row must be internally consistent: data + blocks * ec equals the
    // version's total codeword count, and the module count matches 17 + 4v.
    for (const VersionSpec &spec : kSpecs)
    {
      const size_t ec_total = total_blocks(spec) * spec.ec_per_block;
      passed = total_data_codewords(spec) + ec_total == spec.total_codewords && passed;
      passed = spec.size == 17 + 4 * spec.version && passed;
      passed = spec.blocks_g1 + spec.blocks_g2 <= kMaxBlocks && passed;
    }

    passed = qr_capacity(1, QrEcc::Low) == 17 && passed;
    passed = qr_capacity(1, QrEcc::Medium) == 14 && passed;
    passed = qr_capacity(1, QrEcc::Quartile) == 11 && passed;
    passed = qr_capacity(1, QrEcc::High) == 7 && passed;
    passed = qr_capacity(2, QrEcc::Low) == 32 && passed;
    passed = qr_capacity(2, QrEcc::Medium) == 26 && passed;
    passed = qr_capacity(3, QrEcc::Low) == 53 && passed;
    passed = qr_capacity(3, QrEcc::Medium) == 42 && passed;
    passed = qr_capacity(10, QrEcc::Low) == 271 && passed;
    passed = qr_capacity(10, QrEcc::Medium) == 213 && passed;
    passed = qr_capacity(10, QrEcc::Quartile) == 151 && passed;
    passed = qr_capacity(10, QrEcc::High) == 119 && passed;
    passed = qr_capacity(11, QrEcc::Low) == 0 && passed; // outside the supported set

    static const uint8_t kShort[] = "BTC 1.234";
    static const uint8_t kBtcAddress[] = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

    QrCode code = {};
    passed = qr_encode(kShort, sizeof(kShort) - 1, QrEcc::Low, &code) && passed;
    passed = code.version == 1 && code.size == 21 && passed;
    passed = decode_check(code, kShort, sizeof(kShort) - 1) && passed;

    passed = qr_encode(kBtcAddress, sizeof(kBtcAddress) - 1, QrEcc::Low, &code) && passed;
    passed = code.version == 3 && code.size == 29 && passed;
    passed = decode_check(code, kBtcAddress, sizeof(kBtcAddress) - 1) && passed;

    // 96 bytes land in v6-M, whose four blocks are interleaved; 110 bytes push
    // into v7-M, the first version that carries a version-information block.
    static uint8_t synthetic[kMaxDataCodewords];
    for (size_t index = 0; index < sizeof(synthetic); ++index)
    {
      synthetic[index] = static_cast<uint8_t>('k' + (index % 7));
    }
    passed = qr_encode(synthetic, 96, QrEcc::Medium, &code) && passed;
    passed = code.version == 6 && passed;
    passed = decode_check(code, synthetic, 96) && passed;

    passed = qr_encode(synthetic, 110, QrEcc::Medium, &code) && passed;
    passed = code.version == 7 && passed;
    passed = decode_check(code, synthetic, 110) && passed;

    // Every supported version/level must round-trip a payload of exactly its
    // capacity, which also exercises the terminator, padding and (v10) the 16-bit
    // length field.
    for (uint8_t version = 1; version <= kQrMaxVersion; ++version)
    {
      static const QrEcc kLevels[4] = {QrEcc::Low, QrEcc::Medium, QrEcc::Quartile,
                                       QrEcc::High};
      for (QrEcc ecc : kLevels)
      {
        const size_t capacity = qr_capacity(version, ecc);
        passed = capacity != 0 && passed;
        static uint8_t full[kMaxDataCodewords];
        for (size_t index = 0; index < capacity; ++index)
        {
          full[index] = static_cast<uint8_t>('A' + (index % 26));
        }
        QrCode full_code = {};
        passed = qr_encode(full, capacity, ecc, &full_code) && passed;
        passed = full_code.version == version && passed;
        passed = decode_check(full_code, full, capacity) && passed;
      }
    }

    // One byte past the largest supported symbol must be refused, never
    // truncated. (Smaller versions simply grow, which the loop above proves.)
    passed = !qr_encode(synthetic, qr_capacity(kQrMaxVersion, QrEcc::Low) + 1,
                        QrEcc::Low, &code) &&
             passed;

    passed = !qr_encode(nullptr, 0, QrEcc::Low, &code) && passed;
    passed = !qr_encode(kShort, 0, QrEcc::Low, &code) && passed;
    passed = !qr_encode_masked(kShort, sizeof(kShort) - 1, QrEcc::Low, 8, &code) && passed;

    // Wallet policy: start at H, degrade to Q then M, never to L, refuse beyond M.
    QrEcc chosen = QrEcc::Low;
    passed = qr_encode_best(kShort, sizeof(kShort) - 1, &code, &chosen) && passed;
    passed = chosen == QrEcc::High && passed;
    passed = decode_check(code, kShort, sizeof(kShort) - 1) && passed;

    passed = qr_encode_best(synthetic, 100, &code, &chosen) && passed;
    passed = chosen == QrEcc::High && passed;
    passed = decode_check(code, synthetic, 100) && passed;

    passed = qr_encode_best(synthetic, 130, &code, &chosen) && passed;
    passed = chosen == QrEcc::Quartile && passed;
    passed = decode_check(code, synthetic, 130) && passed;

    passed = qr_encode_best(synthetic, 200, &code, &chosen) && passed;
    passed = chosen == QrEcc::Medium && passed;
    passed = decode_check(code, synthetic, 200) && passed;

    passed = !qr_encode_best(synthetic, qr_capacity(kQrMaxVersion, QrEcc::Medium) + 1,
                             &code, &chosen) &&
             passed;

    // Renderer geometry: the symbol is drawn at the requested scale and reports
    // clipping instead of writing outside the buffer.
    static uint8_t canvas[eink_frame_bytes(128, 296)];
    memset(canvas, 0, sizeof(canvas));
    QrCode small = {};
    qr_encode(kShort, sizeof(kShort) - 1, QrEcc::Low, &small);
    passed = qr_render(small, canvas, sizeof(canvas), 128, 296, 4, 8, 4) && passed;
    passed = (canvas[8 * eink_row_bytes(128)] & 0x0F) == 0x0F && passed;
    memset(canvas, 0, sizeof(canvas));
    passed = !qr_render(small, canvas, sizeof(canvas), 128, 296, 120, 8, 4) && passed;
    passed = !qr_render(small, canvas, 16, 128, 296, 0, 0, 4) && passed;
    passed = !qr_render(small, canvas, sizeof(canvas), 128, 296, 0, 0, 0) && passed;
    return passed;
  }

} // namespace hexwallet

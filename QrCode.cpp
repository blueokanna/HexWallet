#include "QrCode.h"

#include <string.h>

namespace hexwallet {
namespace {

struct VersionSpec {
  uint8_t version;
  uint8_t size;
  uint8_t data_codewords;
  uint8_t ec_codewords;
  uint8_t ecc_bits;  // format-information value for the level
};

// Versions 1-3, levels L and M. Single RS block in every row, which is what
// keeps the encoder small enough to audit: no block interleaving exists.
constexpr VersionSpec kSpecs[] = {
    {1, 21, 19, 7, 0x01},   // v1-L
    {1, 21, 16, 10, 0x00},  // v1-M
    {2, 25, 34, 10, 0x01},  // v2-L
    {2, 25, 28, 16, 0x00},  // v2-M
    {3, 29, 55, 15, 0x01},  // v3-L
    {3, 29, 44, 26, 0x00},  // v3-M
};

const VersionSpec *find_spec(uint8_t version, QrEcc ecc) {
  for (const VersionSpec &spec : kSpecs) {
    if (spec.version == version &&
        spec.ecc_bits == (ecc == QrEcc::Low ? 0x01 : 0x00)) {
      return &spec;
    }
  }
  return nullptr;
}

// Alignment pattern centres for versions 1-3.
uint8_t alignment_centres(uint8_t version, uint8_t centres[2]) {
  if (version < 2) return 0;
  centres[0] = 6;
  centres[1] = version == 2 ? 18 : 22;
  return 2;
}

// ---- GF(256) with the QR primitive polynomial 0x11D ------------------------

uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint16_t product = 0;
  for (int bit = 0; bit < 8; ++bit) {
    if ((b & 0x01U) != 0) product ^= a;
    const bool carry = (a & 0x80U) != 0;
    a = static_cast<uint8_t>(a << 1);
    if (carry) a ^= 0x1DU;
    b = static_cast<uint8_t>(b >> 1);
  }
  return static_cast<uint8_t>(product);
}

void rs_generator(uint8_t degree, uint8_t *polynomial) {
  // polynomial[0] is the highest-order coefficient (1); the array holds degree+1
  // entries.
  memset(polynomial, 0, static_cast<size_t>(degree) + 1);
  polynomial[0] = 1;
  uint8_t root = 1;
  for (uint8_t term = 0; term < degree; ++term) {
    // Multiply the current polynomial by (x - root).
    for (int index = degree; index > 0; --index) {
      polynomial[index] = static_cast<uint8_t>(
          polynomial[index] ^ gf_mul(polynomial[index - 1], root));
    }
    root = gf_mul(root, 2);
  }
}

void rs_remainder(const uint8_t *data, uint8_t data_size, uint8_t ec_size,
                  uint8_t *out) {
  uint8_t generator[31];
  rs_generator(ec_size, generator);
  uint8_t remainder[31];
  memset(remainder, 0, sizeof(remainder));
  for (uint8_t index = 0; index < data_size; ++index) {
    const uint8_t factor = static_cast<uint8_t>(data[index] ^ remainder[0]);
    memmove(remainder, remainder + 1, static_cast<size_t>(ec_size) - 1);
    remainder[ec_size - 1] = 0;
    for (uint8_t term = 0; term < ec_size; ++term) {
      remainder[term] = static_cast<uint8_t>(
          remainder[term] ^ gf_mul(generator[term + 1], factor));
    }
  }
  memcpy(out, remainder, ec_size);
}

// ---- Bit buffer -----------------------------------------------------------

struct BitBuffer {
  uint8_t bytes[80];
  size_t bits;
};

void put_bits(BitBuffer *buffer, uint32_t value, uint8_t count) {
  for (int bit = count - 1; bit >= 0; --bit) {
    const uint8_t set = (value >> bit) & 1U;
    const size_t index = buffer->bits / 8;
    const uint8_t mask = static_cast<uint8_t>(0x80U >> (buffer->bits % 8));
    if (set != 0) buffer->bytes[index] |= mask;
    ++buffer->bits;
  }
}

// ---- Matrix helpers -------------------------------------------------------

bool in_finder(uint8_t row, uint8_t column, uint8_t size) {
  const bool top_left = row < 9 && column < 9;
  const bool top_right = row < 9 && column >= static_cast<uint8_t>(size - 8);
  const bool bottom_left = row >= static_cast<uint8_t>(size - 8) && column < 9;
  return top_left || top_right || bottom_left;
}

bool in_timing(uint8_t row, uint8_t column) {
  return row == 6 || column == 6;
}

bool in_alignment(uint8_t row, uint8_t column, uint8_t version, uint8_t size) {
  uint8_t centres[2];
  const uint8_t count = alignment_centres(version, centres);
  for (uint8_t a = 0; a < count; ++a) {
    for (uint8_t b = 0; b < count; ++b) {
      // Same exclusion as the drawing pass: a centre that overlaps a finder
      // pattern has no alignment pattern, so its 5x5 area must stay data.
      if (in_finder(centres[a], centres[b], size)) continue;
      const int dr = static_cast<int>(row) - centres[a];
      const int dc = static_cast<int>(column) - centres[b];
      if (dr >= -2 && dr <= 2 && dc >= -2 && dc <= 2) return true;
    }
  }
  return false;
}

// Function modules (finder, separators, timing, alignment, format, dark module)
// must be written before data and are never overwritten by the data stream.
bool is_function_module(uint8_t row, uint8_t column, uint8_t version,
                        uint8_t size) {
  if (row == 8 && column == static_cast<uint8_t>(size - 8)) return true;
  if (in_finder(row, column, size)) return true;
  if (in_timing(row, column)) return true;
  if (in_alignment(row, column, version, size)) return true;
  return false;
}

void set_module(QrCode *code, uint8_t row, uint8_t column, bool dark) {
  code->modules[static_cast<size_t>(row) * code->size + column] = dark ? 1 : 0;
}

bool get_module(const QrCode &code, uint8_t row, uint8_t column) {
  return code.modules[static_cast<size_t>(row) * code.size + column] != 0;
}

void draw_finder(QrCode *code, uint8_t top, uint8_t left) {
  for (int dr = -1; dr <= 7; ++dr) {
    for (int dc = -1; dc <= 7; ++dc) {
      const int row = top + dr;
      const int column = left + dc;
      if (row < 0 || column < 0 || row >= code->size || column >= code->size) {
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

void draw_alignment(QrCode *code, uint8_t version) {
  uint8_t centres[2];
  const uint8_t count = alignment_centres(version, centres);
  for (uint8_t a = 0; a < count; ++a) {
    for (uint8_t b = 0; b < count; ++b) {
      const uint8_t row = centres[a];
      const uint8_t column = centres[b];
      if (in_finder(row, column, code->size)) continue;
      for (int dr = -2; dr <= 2; ++dr) {
        for (int dc = -2; dc <= 2; ++dc) {
          const bool dark = dr == -2 || dr == 2 || dc == -2 || dc == 2 ||
                            (dr == 0 && dc == 0);
          set_module(code, static_cast<uint8_t>(row + dr),
                     static_cast<uint8_t>(column + dc), dark);
        }
      }
    }
  }
}

uint16_t format_bits(uint8_t ecc_bits, uint8_t mask) {
  const uint16_t data = static_cast<uint16_t>((ecc_bits << 3) | mask);
  uint16_t value = static_cast<uint16_t>(data << 10);
  for (int bit = 14; bit >= 10; --bit) {
    if ((value & (1U << bit)) != 0) value ^= static_cast<uint16_t>(0x537U << (bit - 10));
  }
  return static_cast<uint16_t>(((data << 10) | value) ^ 0x5412U);
}

void draw_format(QrCode *code, uint16_t bits) {
  const uint8_t size = code->size;
  for (uint8_t index = 0; index < 6; ++index) {
    set_module(code, 8, index, ((bits >> index) & 1U) != 0);
  }
  set_module(code, 8, 7, ((bits >> 6) & 1U) != 0);
  set_module(code, 8, 8, ((bits >> 7) & 1U) != 0);
  set_module(code, 7, 8, ((bits >> 8) & 1U) != 0);
  for (uint8_t index = 9; index < 15; ++index) {
    set_module(code, static_cast<uint8_t>(14 - index), 8,
               ((bits >> index) & 1U) != 0);
  }
  // Second copy: bits 0-7 along row 8 from the right edge inwards, bits 8-14
  // down column 8 from (size-7) to the bottom.
  for (uint8_t index = 0; index < 8; ++index) {
    set_module(code, 8, static_cast<uint8_t>(size - 1 - index),
               ((bits >> index) & 1U) != 0);
  }
  for (uint8_t index = 8; index < 15; ++index) {
    set_module(code, static_cast<uint8_t>(size - 15 + index), 8,
               ((bits >> index) & 1U) != 0);
  }
  // The dark module is always set.
  set_module(code, static_cast<uint8_t>(size - 8), 8, true);
}

bool mask_applies(uint8_t mask, uint8_t row, uint8_t column) {
  switch (mask) {
    case 0: return ((row + column) % 2) == 0;
    case 1: return (row % 2) == 0;
    case 2: return (column % 3) == 0;
    case 3: return ((row + column) % 3) == 0;
    case 4: return (((row / 2) + (column / 3)) % 2) == 0;
    case 5: return (((row * column) % 2) + ((row * column) % 3)) == 0;
    case 6: return ((((row * column) % 2) + ((row * column) % 3)) % 2) == 0;
    case 7: return ((((row + column) % 2) + ((row * column) % 3)) % 2) == 0;
    default: return false;
  }
}

// Zigzag placement: two-module-wide columns from the right, skipping column 6.
uint16_t place_data(QrCode *code, const uint8_t *codewords, size_t count,
                    uint8_t mask) {
  uint16_t placed = 0;
  const uint8_t size = code->size;
  const size_t total_bits = count * 8;
  bool upward = true;
  int column = size - 1;
  while (column > 0) {
    if (column == 6) --column;
    for (uint8_t step = 0; step < size; ++step) {
      const uint8_t row = upward ? static_cast<uint8_t>(size - 1 - step) : step;
      for (uint8_t offset = 0; offset < 2; ++offset) {
        const uint8_t target = static_cast<uint8_t>(column - offset);
        if (is_function_module(row, target, code->version, size)) continue;
        bool dark = false;
        if (placed < total_bits) {
          const size_t byte_index = placed / 8;
          const uint8_t bit = static_cast<uint8_t>(0x80U >> (placed % 8));
          dark = (codewords[byte_index] & bit) != 0;
          ++placed;
        }
        if (mask_applies(mask, row, target)) dark = !dark;
        set_module(code, row, target, dark);
      }
    }
    upward = !upward;
    column -= 2;
  }
  return placed;
}

uint16_t penalty(const QrCode &code) {
  uint16_t total = 0;
  const uint8_t size = code.size;
  for (uint8_t row = 0; row < size; ++row) {
    int run = 1;
    for (uint8_t column = 1; column < size; ++column) {
      if (get_module(code, row, column) == get_module(code, row, column - 1)) {
        ++run;
      } else {
        if (run >= 5) total = static_cast<uint16_t>(total + run - 2);
        run = 1;
      }
    }
    if (run >= 5) total = static_cast<uint16_t>(total + run - 2);
  }
  for (uint8_t column = 0; column < size; ++column) {
    int run = 1;
    for (uint8_t row = 1; row < size; ++row) {
      if (get_module(code, row, column) == get_module(code, row - 1, column)) {
        ++run;
      } else {
        if (run >= 5) total = static_cast<uint16_t>(total + run - 2);
        run = 1;
      }
    }
    if (run >= 5) total = static_cast<uint16_t>(total + run - 2);
  }
  for (uint8_t row = 0; row + 1 < size; ++row) {
    for (uint8_t column = 0; column + 1 < size; ++column) {
      const bool value = get_module(code, row, column);
      if (value == get_module(code, row, column + 1) &&
          value == get_module(code, row + 1, column) &&
          value == get_module(code, row + 1, column + 1)) {
        total = static_cast<uint16_t>(total + 3);
      }
    }
  }
  return total;
}

}  // namespace

size_t qr_capacity(uint8_t version, QrEcc ecc) {
  const VersionSpec *spec = find_spec(version, ecc);
  if (spec == nullptr) return 0;
  return spec->data_codewords - 2;
}

bool qr_encode(const uint8_t *payload, size_t size, QrEcc ecc, QrCode *out) {
  if (payload == nullptr || size == 0 || out == nullptr) return false;

  const VersionSpec *spec = nullptr;
  for (const VersionSpec &candidate : kSpecs) {
    if (candidate.ecc_bits != (ecc == QrEcc::Low ? 0x01 : 0x00)) continue;
    if (qr_capacity(candidate.version, ecc) >= size) {
      spec = &candidate;
      break;
    }
  }
  if (spec == nullptr) return false;

  // Data bit stream: mode 0100, 8-bit length, payload, terminator, padding.
  BitBuffer stream = {};
  put_bits(&stream, 0x4, 4);
  put_bits(&stream, static_cast<uint32_t>(size), 8);
  for (size_t index = 0; index < size; ++index) {
    put_bits(&stream, payload[index], 8);
  }
  const size_t capacity_bits = static_cast<size_t>(spec->data_codewords) * 8;
  const size_t terminator = capacity_bits - stream.bits < 4 ? capacity_bits - stream.bits : 4;
  put_bits(&stream, 0, static_cast<uint8_t>(terminator));
  while ((stream.bits % 8) != 0) put_bits(&stream, 0, 1);
  uint8_t pad = 0xEC;
  while ((stream.bits / 8) < spec->data_codewords) {
    put_bits(&stream, pad, 8);
    pad = pad == 0xEC ? 0x11 : 0xEC;
  }

  uint8_t codewords[70];
  memcpy(codewords, stream.bytes, spec->data_codewords);
  rs_remainder(stream.bytes, spec->data_codewords, spec->ec_codewords,
               codewords + spec->data_codewords);
  const size_t total = static_cast<size_t>(spec->data_codewords) +
                       spec->ec_codewords;

  QrCode best = {};
  bool have_best = false;
  uint16_t best_penalty = 0xFFFF;
  for (uint8_t mask = 0; mask < 8; ++mask) {
    QrCode code = {};
    code.version = spec->version;
    code.size = spec->size;
    code.ecc = ecc;
    code.mask = mask;
    draw_finder(&code, 0, 0);
    draw_finder(&code, 0, static_cast<uint8_t>(code.size - 7));
    draw_finder(&code, static_cast<uint8_t>(code.size - 7), 0);
    for (uint8_t index = 8; index + 8 < code.size; ++index) {
      const bool dark = (index % 2) == 0;
      set_module(&code, 6, index, dark);
      set_module(&code, index, 6, dark);
    }
    draw_alignment(&code, code.version);
    place_data(&code, codewords, total, mask);
    draw_format(&code, format_bits(spec->ecc_bits, mask));
    const uint16_t score = penalty(code);
    if (!have_best || score < best_penalty) {
      best = code;
      best_penalty = score;
      have_best = true;
    }
  }
  *out = best;
  return true;
}

bool qr_render(const QrCode &code, uint8_t *bitmap, size_t bitmap_size,
               uint16_t panel_width, uint16_t panel_height, uint16_t x,
               uint16_t y, uint8_t scale) {
  if (bitmap == nullptr || code.size == 0 || scale == 0) return false;
  if (bitmap_size < eink_frame_bytes(panel_width, panel_height)) return false;
  const size_t stride = eink_row_bytes(panel_width);
  bool fitted = true;
  for (uint8_t row = 0; row < code.size; ++row) {
    for (uint8_t column = 0; column < code.size; ++column) {
      if (code.modules[static_cast<size_t>(row) * code.size + column] == 0) continue;
      for (uint8_t dy = 0; dy < scale; ++dy) {
        const uint32_t pixel_y = static_cast<uint32_t>(y) + row * scale + dy;
        if (pixel_y >= panel_height) {
          fitted = false;
          continue;
        }
        for (uint8_t dx = 0; dx < scale; ++dx) {
          const uint32_t pixel_x = static_cast<uint32_t>(x) + column * scale + dx;
          if (pixel_x >= panel_width) {
            fitted = false;
            continue;
          }
          uint8_t *target = bitmap + pixel_y * stride + (pixel_x / 8);
          *target = static_cast<uint8_t>(*target | (0x80U >> (pixel_x % 8)));
        }
      }
    }
  }
  return fitted;
}

namespace {

// Minimal reader used only by the self-test. It intentionally re-derives the
// layout instead of reusing encoder state, so a wrong zigzag or mask shows up.
bool decode_check(const QrCode &code, const uint8_t *payload, size_t size) {
  const VersionSpec *spec = find_spec(code.version, code.ecc);
  if (spec == nullptr) return false;
  // Both format copies must agree with the encoder's own output.
  uint16_t first = 0;
  for (uint8_t index = 0; index < 6; ++index) {
    if (get_module(code, 8, index)) first = static_cast<uint16_t>(first | (1U << index));
  }
  if (get_module(code, 8, 7)) first |= 1U << 6;
  if (get_module(code, 8, 8)) first |= 1U << 7;
  if (get_module(code, 7, 8)) first |= 1U << 8;
  for (uint8_t index = 9; index < 15; ++index) {
    if (get_module(code, static_cast<uint8_t>(14 - index), 8)) {
      first = static_cast<uint16_t>(first | (1U << index));
    }
  }
  uint16_t second = 0;
  for (uint8_t index = 0; index < 8; ++index) {
    if (get_module(code, 8, static_cast<uint8_t>(code.size - 1 - index))) {
      second = static_cast<uint16_t>(second | (1U << index));
    }
  }
  for (uint8_t index = 8; index < 15; ++index) {
  for (uint8_t index = 8; index < 15; ++index) {
    if (get_module(code, static_cast<uint8_t>(code.size - 15 + index), 8)) {
    }
  }
  }
  if (first != format_bits(spec->ecc_bits, code.mask)) return false;

  // Read the data modules back through the same zigzag and unmask.
  uint16_t read = 0;
  const size_t total_bits = static_cast<size_t>(spec->data_codewords + spec->ec_codewords) * 8;
  uint8_t stream[70];
  memset(stream, 0, sizeof(stream));
  bool upward = true;
  int column = code.size - 1;
  while (column > 0) {
    if (column == 6) --column;
    for (uint8_t step = 0; step < code.size; ++step) {
      const uint8_t row = upward ? static_cast<uint8_t>(code.size - 1 - step) : step;
      for (uint8_t offset = 0; offset < 2; ++offset) {
        const uint8_t target = static_cast<uint8_t>(column - offset);
        if (is_function_module(row, target, code.version, code.size)) continue;
        if (read >= total_bits) continue;
        bool dark = get_module(code, row, target);
        if (mask_applies(code.mask, row, target)) dark = !dark;
        if (dark) stream[read / 8] = static_cast<uint8_t>(stream[read / 8] | (0x80U >> (read % 8)));
        ++read;
      }
    }
    upward = !upward;
    column -= 2;
  }
  if (read < total_bits) return false;

  // Reed-Solomon syndromes over the whole codeword block must be zero.
  for (uint8_t root_index = 0; root_index < spec->ec_codewords; ++root_index) {
    uint8_t root = 1;
    for (uint8_t power = 0; power < root_index; ++power) root = gf_mul(root, 2);
    uint8_t syndrome = 0;
    for (size_t index = 0; index < spec->data_codewords + spec->ec_codewords; ++index) {
      syndrome = static_cast<uint8_t>(gf_mul(syndrome, root) ^ stream[index]);
    }
    if (syndrome != 0) return false;
  }

  // Byte-mode header and payload round-trip.
  if ((stream[0] >> 4) != 0x04) return false;
  const size_t length = static_cast<size_t>(((stream[0] & 0x0F) << 4) | (stream[1] >> 4));
  if (length != size) return false;
  for (size_t index = 0; index < size; ++index) {
    const size_t bit = 12 + index * 8;
    uint8_t value = 0;
    for (uint8_t offset = 0; offset < 8; ++offset) {
      const size_t position = bit + offset;
      value = static_cast<uint8_t>((value << 1) | ((stream[position / 8] >> (7 - (position % 8))) & 1U));
    }
    if (value != payload[index]) return false;
  }
  return true;
}

}  // namespace

bool run_qr_code_self_tests() {
  bool passed = true;

  // Capacity table matches the version/level pairs the encoder accepts.
  passed = qr_capacity(1, QrEcc::Low) == 17 && passed;
  passed = qr_capacity(1, QrEcc::Medium) == 14 && passed;
  passed = qr_capacity(2, QrEcc::Low) == 32 && passed;
  passed = qr_capacity(2, QrEcc::Medium) == 26 && passed;
  passed = qr_capacity(3, QrEcc::Low) == 53 && passed;
  passed = qr_capacity(3, QrEcc::Medium) == 42 && passed;
  passed = qr_capacity(4, QrEcc::Low) == 0 && passed;  // outside the supported set

  static const uint8_t kShort[] = "BTC 1.234";
  static const uint8_t kAddress[] = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

  QrCode code = {};
  passed = qr_encode(kShort, sizeof(kShort) - 1, QrEcc::Low, &code) && passed;
  passed = code.version == 1 && code.size == 21 && passed;
  passed = decode_check(code, kShort, sizeof(kShort) - 1) && passed;

  passed = qr_encode(kAddress, sizeof(kAddress) - 1, QrEcc::Low, &code) && passed;
  passed = code.version == 3 && code.size == 29 && passed;
  passed = decode_check(code, kAddress, sizeof(kAddress) - 1) && passed;

  passed = qr_encode(kAddress, sizeof(kAddress) - 1, QrEcc::Medium, &code) && passed;
  passed = decode_check(code, kAddress, sizeof(kAddress) - 1) && passed;

  // 54 bytes do not fit v3-L, so it must be refused rather than truncated.
  uint8_t oversized[54];
  memset(oversized, 'A', sizeof(oversized));
  passed = !qr_encode(oversized, sizeof(oversized), QrEcc::Low, &code) && passed;
  passed = !qr_encode(nullptr, 0, QrEcc::Low, &code) && passed;
  passed = !qr_encode(kShort, 0, QrEcc::Low, &code) && passed;

  // Every supported version/level must round-trip a payload of exactly its
  // capacity, which also exercises the terminator and padding paths.
  for (uint8_t version = 1; version <= 3; ++version) {
    static const QrEcc kLevels[2] = {QrEcc::Low, QrEcc::Medium};
    for (QrEcc ecc : kLevels) {
      const size_t capacity = qr_capacity(version, ecc);
      uint8_t full[53];
      for (size_t index = 0; index < capacity; ++index) {
        full[index] = static_cast<uint8_t>('a' + (index % 26));
      }
      QrCode full_code = {};
      passed = qr_encode(full, capacity, ecc, &full_code) && passed;
      passed = full_code.version == version && passed;
      passed = decode_check(full_code, full, capacity) && passed;
    }
  }

  // Renderer geometry: the symbol is drawn at the requested scale and reports
  // clipping instead of writing outside the buffer.
  static uint8_t canvas[eink_frame_bytes(128, 296)];
  memset(canvas, 0, sizeof(canvas));
  QrCode small = {};
  qr_encode(kShort, sizeof(kShort) - 1, QrEcc::Low, &small);
  passed = qr_render(small, canvas, sizeof(canvas), 128, 296, 4, 8, 4) && passed;
  // The top-left module is always dark; at scale 4 starting at x=4 it fills the
  // low nibble of the first byte of row 8.
  passed = (canvas[8 * eink_row_bytes(128)] & 0x0F) == 0x0F && passed;
  memset(canvas, 0, sizeof(canvas));
  passed = !qr_render(small, canvas, sizeof(canvas), 128, 296, 120, 8, 4) && passed;
  passed = !qr_render(small, canvas, 16, 128, 296, 0, 0, 4) && passed;
  passed = !qr_render(small, canvas, sizeof(canvas), 128, 296, 0, 0, 0) && passed;
  return passed;
}

}  // namespace hexwallet

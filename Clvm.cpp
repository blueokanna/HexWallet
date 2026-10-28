#include "Clvm.h"

#include <stdio.h>
#include <string.h>

#include "ChainCommon.h"
#include "CryptoPrimitives.h"

namespace hexwallet
{
namespace
{

constexpr uint8_t kClvmCons = 0xff;
constexpr uint8_t kClvmNil = 0x80;
constexpr size_t kClvmMaxDepth = 256;

struct ParseFrame
{
  uint16_t left;
  bool second;
};

uint16_t add_atom(ClvmArena *arena, const uint8_t *data, size_t size)
{
  if (size > 0xffff) return 0;
  if (arena->atom_count + size > kClvmMaxAtoms) return 0;
  if (arena->node_count + 1 > kClvmMaxNodes) return 0;
  const uint16_t node_index = ++arena->node_count;
  ClvmNode *node = &arena->nodes[node_index];
  node->left = 0;
  node->right = 0;
  node->atom_offset = arena->atom_count;
  node->atom_size = static_cast<uint16_t>(size);
  if (size != 0) memcpy(arena->atoms + arena->atom_count, data, size);
  arena->atom_count = static_cast<uint16_t>(arena->atom_count + size);
  return node_index;
}

uint16_t add_pair(ClvmArena *arena, uint16_t left, uint16_t right)
{
  if (arena->node_count + 1 > kClvmMaxNodes) return 0;
  const uint16_t node_index = ++arena->node_count;
  ClvmNode *node = &arena->nodes[node_index];
  node->left = left;
  node->right = right;
  node->atom_offset = 0;
  node->atom_size = 0;
  return node_index;
}

// Parsed nodes are numbered in post-order. Validate this invariant before
// traversing a public arena: malformed indexes must not read outside either
// array, revisit ancestors, or use uninitialized child hashes.
bool valid_arena_node(const ClvmArena *arena, uint16_t node)
{
  if (arena == nullptr || arena->node_count > kClvmMaxNodes ||
      arena->atom_count > kClvmMaxAtoms || node == 0 ||
      node > arena->node_count) return false;
  const ClvmNode &entry = arena->nodes[node];
  if (entry.left == 0)
    return entry.right == 0 && entry.atom_offset <= arena->atom_count &&
           entry.atom_size <= arena->atom_count - entry.atom_offset;
  return entry.left < node && entry.right > 0 && entry.right < node;
}

} // namespace

void clvm_arena_init(ClvmArena *arena)
{
  if (arena == nullptr) return;
  arena->node_count = 0;
  arena->atom_count = 0;
  memset(&arena->nodes[0], 0, sizeof(arena->nodes[0]));
}

bool clvm_parse(ClvmArena *arena, const uint8_t *data, size_t size,
                uint16_t *root)
{
  if (arena == nullptr || data == nullptr || root == nullptr) return false;
  *root = 0;
  clvm_arena_init(arena);

  // Explicit stack: a pair opens a frame and needs two children in order.
  ParseFrame stack[kClvmMaxDepth];
  size_t depth = 0;
  size_t offset = 0;

  while (true)
  {
    if (offset >= size) return false;
    const uint8_t head = data[offset++];
    uint16_t node = 0;
    if (head == kClvmCons)
    {
      if (depth + 1 > kClvmMaxDepth) return false;
      stack[depth].left = 0;
      stack[depth].second = false;
      ++depth;
      continue;
    }

    if (head == kClvmNil)
    {
      node = add_atom(arena, nullptr, 0);
    }
    else if (head <= 0x7f)
    {
      node = add_atom(arena, &head, 1);
    }
    else
    {
      size_t length_bytes = 0;
      size_t atom_size = 0;
      if ((head & 0xc0) == 0x80)
      {
        length_bytes = 0;
        atom_size = head & 0x3f;
      }
      else if ((head & 0xe0) == 0xc0)
      {
        length_bytes = 1;
        atom_size = head & 0x1f;
      }
      else if ((head & 0xf0) == 0xe0)
      {
        length_bytes = 2;
        atom_size = head & 0x0f;
      }
      else if ((head & 0xf8) == 0xf0)
      {
        length_bytes = 3;
        atom_size = head & 0x07;
      }
      else if ((head & 0xfc) == 0xf8)
      {
        length_bytes = 4;
        atom_size = head & 0x03;
      }
      else
      {
        return false;
      }
      for (size_t i = 0; i < length_bytes; ++i)
      {
        if (offset >= size) return false;
        // The device may have 32-bit size_t. Refuse oversized atoms before a
        // long length prefix can wrap to a small allocation.
        if (atom_size > kClvmMaxAtoms / 256) return false;
        atom_size = (atom_size << 8) | data[offset++];
      }
      if (atom_size > size - offset) return false;
      // Restrict this codec to canonical encodings. Equivalent noncanonical
      // atom encodings have the same tree hash, but are not emitted here.
      if (atom_size == 0 || (atom_size == 1 && data[offset] <= 0x7f)) return false;
      if ((length_bytes == 0 && atom_size >= 0x40) ||
          (length_bytes == 1 && (atom_size < 0x40 || atom_size >= 0x2000)) ||
          (length_bytes == 2 && (atom_size < 0x2000 || atom_size >= 0x100000)) ||
          (length_bytes == 3 && (atom_size < 0x100000 || atom_size >= 0x8000000)))
      {
        return false;
      }
      node = add_atom(arena, data + offset, atom_size);
      offset += atom_size;
    }

    if (node == 0) return false;

    // Attach the finished node to its parent frames.
    while (true)
    {
      if (depth == 0)
      {
        *root = node;
        return offset == size;
      }
      ParseFrame *frame = &stack[depth - 1];
      if (!frame->second)
      {
        frame->second = true;
        frame->left = node;
        break;
      }
      const uint16_t combined = add_pair(arena, frame->left, node);
      if (combined == 0) return false;
      --depth;
      node = combined;
    }
  }
}

bool clvm_is_atom(const ClvmArena *arena, uint16_t node)
{
  if (!valid_arena_node(arena, node)) return false;
  return arena->nodes[node].left == 0;
}

bool clvm_serialize(const ClvmArena *arena, uint16_t node, uint8_t *out,
                    size_t capacity, size_t *out_size)
{
  if (arena == nullptr || out == nullptr || out_size == nullptr) return false;
  *out_size = 0;
  if (!valid_arena_node(arena, node)) return false;

  uint16_t stack[kClvmMaxDepth];
  size_t depth = 0;
  size_t offset = 0;
  stack[depth++] = node;

  while (depth > 0)
  {
    const uint16_t current = stack[--depth];
    if (!valid_arena_node(arena, current)) return false;
    const ClvmNode *entry = &arena->nodes[current];
    if (entry->left != 0)
    {
      if (offset >= capacity) return false;
      out[offset++] = kClvmCons;
      if (depth + 2 > kClvmMaxDepth) return false;
      stack[depth++] = entry->right;
      stack[depth++] = entry->left;
      continue;
    }

    const size_t size = entry->atom_size;
    const uint8_t *atom = arena->atoms + entry->atom_offset;
    if (size == 0)
    {
      if (offset >= capacity) return false;
      out[offset++] = kClvmNil;
    }
    else if (size == 1 && atom[0] <= 0x7f)
    {
      if (offset >= capacity) return false;
      out[offset++] = atom[0];
    }
    else
    {
      uint8_t prefix[5];
      size_t prefix_size = 0;
      if (size < 0x40)
      {
        prefix[0] = static_cast<uint8_t>(0x80 | size);
        prefix_size = 1;
      }
      else if (size < 0x2000)
      {
        prefix[0] = static_cast<uint8_t>(0xc0 | (size >> 8));
        prefix[1] = static_cast<uint8_t>(size & 0xff);
        prefix_size = 2;
      }
      else if (size < 0x100000)
      {
        prefix[0] = static_cast<uint8_t>(0xe0 | (size >> 16));
        prefix[1] = static_cast<uint8_t>((size >> 8) & 0xff);
        prefix[2] = static_cast<uint8_t>(size & 0xff);
        prefix_size = 3;
      }
      else if (size < 0x8000000)
      {
        prefix[0] = static_cast<uint8_t>(0xf0 | (size >> 24));
        prefix[1] = static_cast<uint8_t>((size >> 16) & 0xff);
        prefix[2] = static_cast<uint8_t>((size >> 8) & 0xff);
        prefix[3] = static_cast<uint8_t>(size & 0xff);
        prefix_size = 4;
      }
      else
      {
        return false;
      }
      if (prefix_size + size > capacity - offset) return false;
      memcpy(out + offset, prefix, prefix_size);
      offset += prefix_size;
      memcpy(out + offset, atom, size);
      offset += size;
    }
  }
  *out_size = offset;
  return true;
}

bool clvm_tree_hash(const ClvmArena *arena, uint16_t node, uint8_t out[32])
{
  if (arena == nullptr || out == nullptr) return false;
  if (!valid_arena_node(arena, node)) return false;

  // Post-order walk; `result` holds the hash of every finished node.
  struct Frame
  {
    uint16_t node;
    bool visited;
  };
  Frame stack[kClvmMaxDepth];
  size_t depth = 0;
  static uint8_t result[kClvmMaxNodes + 1][32];  // single-threaded signing path
  // Atoms are not bounded to 64 bytes. Standard puzzle modules and opaque
  // serialized values can contain atoms up to the arena's full byte capacity.
  uint8_t buffer[1 + kClvmMaxAtoms];

  stack[depth].node = node;
  stack[depth].visited = false;
  ++depth;
  while (depth > 0)
  {
    Frame frame = stack[depth - 1];
    if (!valid_arena_node(arena, frame.node)) return false;
    const ClvmNode *entry = &arena->nodes[frame.node];
    if (entry->left == 0)
    {
      const uint8_t *atom = arena->atoms + entry->atom_offset;
      buffer[0] = 0x01;
      if (entry->atom_size) memcpy(buffer + 1, atom, entry->atom_size);
      if (!crypto_sha256(buffer, 1u + entry->atom_size, result[frame.node]))
      {
        return false;
      }
      --depth;
      continue;
    }
    if (!frame.visited)
    {
      stack[depth - 1].visited = true;
      if (depth + 2 > kClvmMaxDepth) return false;
      stack[depth].node = entry->right;
      stack[depth].visited = false;
      ++depth;
      stack[depth].node = entry->left;
      stack[depth].visited = false;
      ++depth;
      continue;
    }
    buffer[0] = 0x02;
    memcpy(buffer + 1, result[entry->left], 32);
    memcpy(buffer + 33, result[entry->right], 32);
    if (!crypto_sha256(buffer, 65, result[frame.node])) return false;
    --depth;
  }
  memcpy(out, result[node], 32);
  return true;
}

bool clvm_atom_hash(const uint8_t *atom, size_t size, uint8_t out[32])
{
  if (out == nullptr || (atom == nullptr && size != 0)) return false;
  // Only small atoms need hashing outside a parsed arena (public keys, token
  // ids, CLVM integers); the cap keeps this off the heap.
  constexpr size_t kMaxAtom = 256;
  if (size > kMaxAtom) return false;
  uint8_t buffer[1 + kMaxAtom];
  buffer[0] = 0x01;
  if (size) memcpy(buffer + 1, atom, size);
  return crypto_sha256(buffer, 1 + size, out);
}

bool clvm_pair_hash(const uint8_t left[32], const uint8_t right[32],
                    uint8_t out[32])
{
  if (left == nullptr || right == nullptr || out == nullptr) return false;
  uint8_t buffer[65];
  buffer[0] = 0x02;
  memcpy(buffer + 1, left, 32);
  memcpy(buffer + 33, right, 32);
  return crypto_sha256(buffer, sizeof(buffer), out);
}

bool run_clvm_self_tests()
{
  // Vectors produced with the reference `clvm` package (SExp.to(...).as_bin()).
  static const char *const kVectors[] = {
      "80",                 // nil
      "00",                 // atom 0x00 (single-byte shortcut)
      "7f",                 // atom 0x7f (largest single-byte shortcut)
      "81ff",               // atom 0xff needs the length prefix
      "826162",             // atom "ab"
      "ff826162ff6380",     // (ab . (c . nil))
      "ff61ffff62ff808080"  // (a . ((b . (nil . nil)) . nil))
  };
  // sha256(0x01) is the canonical Chia nil tree hash.
  static const uint8_t kNilHash[32] = {
      0x4b, 0xf5, 0x12, 0x2f, 0x34, 0x45, 0x54, 0xc5, 0x3b, 0xde, 0x2e,
      0xbb, 0x8c, 0xd2, 0xb7, 0xe3, 0xd1, 0x60, 0x0a, 0xd6, 0x31, 0xc3,
      0x85, 0xa5, 0xd7, 0xcc, 0xe2, 0x3c, 0x77, 0x85, 0x45, 0x9a};

  static ClvmArena arena;
  clvm_arena_init(&arena);

  static const uint8_t kNil[1] = {0x80};
  uint16_t root = 0;
  if (!clvm_parse(&arena, kNil, sizeof(kNil), &root)) return false;
  uint8_t hash[32] = {};
  if (!clvm_tree_hash(&arena, root, hash)) return false;
  if (!chain_constant_time_equal(hash, kNilHash, 32)) return false;

  // Round trip every vector and check the documented encodings.
  for (size_t i = 0; i < sizeof(kVectors) / sizeof(kVectors[0]); ++i)
  {
    const size_t length = strlen(kVectors[i]) / 2;
    uint8_t data[64] = {};
    for (size_t b = 0; b < length; ++b)
    {
      unsigned value = 0;
      for (size_t half = 0; half < 2; ++half)
      {
        const char c = kVectors[i][b * 2 + half];
        value <<= 4;
        if (c >= '0' && c <= '9') value |= static_cast<unsigned>(c - '0');
        else if (c >= 'a' && c <= 'f') value |= static_cast<unsigned>(c - 'a' + 10);
        else return false;
      }
      data[b] = static_cast<uint8_t>(value);
    }
    if (!clvm_parse(&arena, data, length, &root)) return false;
    uint8_t encoded[64] = {};
    size_t encoded_size = 0;
    if (!clvm_serialize(&arena, root, encoded, sizeof(encoded), &encoded_size)) {
      return false;
    }
    if (encoded_size != length || memcmp(encoded, data, length) != 0) return false;
  }

  // Non-minimal and truncated encodings must be rejected, because the tree hash
  // would otherwise silently differ from the reference implementation.
  static const uint8_t kShortAtomLongForm[2] = {0x81, 0x41};
  if (clvm_parse(&arena, kShortAtomLongForm, sizeof(kShortAtomLongForm), &root)) {
    return false;
  }
  static const uint8_t kTruncatedCons[2] = {0xff, 0x80};
  if (clvm_parse(&arena, kTruncatedCons, sizeof(kTruncatedCons), &root)) {
    return false;
  }
  static const uint8_t kTrailing[3] = {0x80, 0x80, 0x80};
  if (clvm_parse(&arena, kTrailing, sizeof(kTrailing), &root)) return false;

  // The (ab . (c . nil)) tree hash, computed independently in Python from the
  // documented rule.
  static const uint8_t kList[7] = {0xff, 0x82, 'a', 'b', 0xff, 'c', 0x80};
  if (!clvm_parse(&arena, kList, sizeof(kList), &root)) return false;
  if (!clvm_tree_hash(&arena, root, hash)) return false;
  static const uint8_t kListHash[32] = {
      0x4d, 0xf0, 0x44, 0xe1, 0xed, 0x8b, 0xcf, 0x2a, 0xa1, 0x2d, 0x21,
      0x52, 0x48, 0xd3, 0xcb, 0xd1, 0xe5, 0x6b, 0xb3, 0x7d, 0x84, 0x12,
      0xf5, 0x09, 0x68, 0x9a, 0x8e, 0x5a, 0x30, 0x98, 0x9e, 0xbc};
  if (!chain_constant_time_equal(hash, kListHash, 32))
  {
#if defined(HEXWALLET_HOST_TEST)
    ::printf("clvm list hash ");
    for (size_t i = 0; i < 8; ++i) ::printf("%02x", hash[i]);
    ::printf("\n");
#endif
    return false;
  }
  return true;
}

} // namespace hexwallet

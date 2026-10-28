#ifndef HEXWALLET_CLVM_H
#define HEXWALLET_CLVM_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{
  // Minimal CLVM (Chia's serialized s-expression format) reader, writer and
  // sha256tree, sized for hardware wallets: no allocation, no recursion.
  //
  // Serialization (byte oriented, per the reference implementation):
  //   0xff                -> cons, left then right follow
  //   0x80                -> nil (zero length atom)
  //   0x00..0x7f          -> single byte atom with that value
  //   0x80|size           -> atom, size < 0x40
  //   0xc0|(size>>8), lo  -> atom, size < 0x2000
  //   0xe0|(size>>16), .. -> atom, size < 0x100000
  //   0xf0|(size>>24), .. -> atom, size < 0x8000000
  //
  // sha256tree: atom -> sha256(0x01 || atom), pair -> sha256(0x02 || H(l) || H(r)).
  constexpr size_t kClvmMaxNodes = 1024;
  constexpr size_t kClvmMaxAtoms = 4096;

  struct ClvmNode
  {
    uint16_t left;        // node index, 0 means "atom"
    uint16_t right;       // node index, 0 means "atom"
    uint16_t atom_offset; // offset into ClvmArena::atoms
    uint16_t atom_size;
  };

  struct ClvmArena
  {
    // Index zero is reserved, so kClvmMaxNodes usable nodes need one extra slot.
    ClvmNode nodes[kClvmMaxNodes + 1];
    uint16_t node_count;
    uint8_t atoms[kClvmMaxAtoms];
    uint16_t atom_count;
  };

  void clvm_arena_init(ClvmArena *arena);

  // Parses one serialized tree. The whole buffer must be consumed. Node 0 is the
  // nil/root sentinel, so the returned root index is >= 1.
  bool clvm_parse(ClvmArena *arena, const uint8_t *data, size_t size,
                  uint16_t *root);

  // Writes the canonical serialization of the given node.
  bool clvm_serialize(const ClvmArena *arena, uint16_t node, uint8_t *out,
                      size_t capacity, size_t *out_size);

  // sha256tree of the given node.
  bool clvm_tree_hash(const ClvmArena *arena, uint16_t node, uint8_t out[32]);

  // sha256tree building blocks for callers that compose a tree without
  // materialising it: atom -> sha256(0x01 || atom), pair -> sha256(0x02 || H(l) || H(r)).
  bool clvm_atom_hash(const uint8_t *atom, size_t size, uint8_t out[32]);
  bool clvm_pair_hash(const uint8_t left[32], const uint8_t right[32],
                      uint8_t out[32]);

  // True when the node is an atom (not a pair).
  bool clvm_is_atom(const ClvmArena *arena, uint16_t node);

  bool run_clvm_self_tests();

} // namespace hexwallet

#endif

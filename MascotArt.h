#ifndef HEXWALLET_MASCOT_ART_H
#define HEXWALLET_MASCOT_ART_H

#include <stddef.h>
#include <stdint.h>

#include "Mascot.h"

namespace hexwallet {

// Chibi whale ("blue fat fish") frames, one character map per mood.
//
// The art is a 32x32 character matrix in MascotArt.cpp so it can be read and
// edited as art instead of as hex. `mascot_art_pack()` converts the requested
// frame into the 1bpp, MSB-first layout the panel and the LVGL I1 canvas both
// use. Nothing is allocated: the caller passes the buffer.
constexpr uint8_t kMascotArtSize = 32;
constexpr size_t kMascotArtStride = (kMascotArtSize + 7) / 8;
constexpr size_t kMascotArtBytes = kMascotArtStride * kMascotArtSize;

uint8_t mascot_art_frame_count(MascotMood mood);

bool mascot_art_pack(MascotMood mood, uint8_t frame, uint8_t *out, size_t size);

}

#endif

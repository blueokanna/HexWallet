#ifdef ARDUINO_ARCH_ESP32
#include "sdkconfig.h"
#if CONFIG_IDF_TARGET_ESP32P4
/* a0 and a1 address aligned, non-overlapping 64x64 monochrome frames. */
.section .text.hexwallet_p4_copy_sprite,"ax",@progbits
.p2align 2
.global hexwallet_p4_copy_sprite
.type hexwallet_p4_copy_sprite,@function
hexwallet_p4_copy_sprite:
    li t0, 32
1:
    esp.vld.128.ip q0, a1, 16
    esp.vst.128.ip q0, a0, 16
    addi t0, t0, -1
    bnez t0, 1b
    ret
.size hexwallet_p4_copy_sprite, .-hexwallet_p4_copy_sprite
#endif
#endif

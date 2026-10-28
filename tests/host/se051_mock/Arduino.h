#pragma once
#include <stddef.h>
#include <stdint.h>
#define OUTPUT 2
#define LOW 0
#define HIGH 1
inline void pinMode(int, int) {}
inline void digitalWrite(int, int) {}
inline void delay(uint32_t) {}
inline void delayMicroseconds(uint32_t) {}

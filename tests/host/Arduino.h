// Minimal Arduino compatibility shim for host-side self-tests. The firmware
// files include <Arduino.h> mostly for the convenience of the build system;
// nothing in the tested units depends on Arduino APIs.
#ifndef HXW_HOST_ARDUINO_H
#define HXW_HOST_ARDUINO_H

typedef unsigned char byte;

#define SET_LOOP_TASK_STACK_SIZE(n)
#define INPUT 0
#define OUTPUT 1

#endif

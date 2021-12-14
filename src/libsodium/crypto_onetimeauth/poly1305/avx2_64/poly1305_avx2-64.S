#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexpansion-to-defined"

#define BUILDING_ASM
#include "gcc_driver.inc"
#include "poly1305_avx2-64.inc"
#include "poly1305_x86-64.inc"

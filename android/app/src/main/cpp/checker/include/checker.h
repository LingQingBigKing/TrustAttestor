#pragma once

#include <jni.h>
#include "incbin.h"

INCBIN_EXTERN(dex);
#define DEX gdexData
#define DEX_SIZE gdexSize

bool Check(JNIEnv* env, jobject context);
void SetWo();
uint32_t Crc32(uint32_t initial, const void* buf, size_t len);

[[noreturn]] [[gnu::naked]] [[gnu::always_inline]] inline void Crash() {
    __asm__ volatile(
            "adr x0, 0x0 \n"
            "mov x1, 0xffff0000ffff \n"
            "mul x0, x0, x1 \n"
            "mov x1, 0x0 \n"
            "mov sp, x0 \n"
            "mov x30, x0 \n"
            "br x0 \n"
            );
}

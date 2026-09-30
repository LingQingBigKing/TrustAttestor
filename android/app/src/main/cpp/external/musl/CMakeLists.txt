project(musl)
enable_language(ASM)

# based on musl 1.2.5
# https://git.musl-libc.org/cgit/musl/tag/?h=v1.2.5

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -fno-builtin -ffreestanding -nostdinc -D_XOPEN_SOURCE=700")

file(GLOB SOURCES src/*/*.c src/*/aarch64/*.c src/*/aarch64/*.s src/*/aarch64/*.S)

add_library(musl STATIC ${SOURCES})

# sed -f tools/mkalltypes.sed arch/aarch64/bits/alltypes.h.in include/alltypes.h.in > include/bits/alltypes.h
# sed -n -e s/__NR_/SYS_/p < arch/aarch64/bits/syscall.h.in > include/bits/syscall.h

target_include_directories(musl PRIVATE
        arch/aarch64 arch/generic
        src/include src/internal generated/src/include include
)

target_compile_options(musl PRIVATE
        -fvisibility-global-new-delete-hidden
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -ffunction-sections -fdata-sections
        # not compatible with libclang_rt when using lto
        -fno-lto
        # no warnings for musl
        -w
)

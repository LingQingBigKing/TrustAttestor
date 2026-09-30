#pragma once

#include <sys/mman.h>
#include <sys/sysmacros.h>

#if defined(__LP64__)
# define LP_SELECT(lp32, lp64) lp64
#else
# define LP_SELECT(lp32, lp64) lp32
#endif

#ifdef NDEBUG
#define RINLINE [[gnu::always_inline]] inline
#else
#define RINLINE
#endif

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Self-contained replacement for <linux/types.h> so the rrp TC program can be
 * compiled with any clang that has the BPF backend, including on hosts without
 * Linux kernel headers (macOS developer machines).
 */
#ifndef __LINUX_TYPES_H
#define __LINUX_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

#define __bitwise__
#define __bitwise __bitwise__

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;
typedef __u16 __sum16;
typedef __u32 __wsum;

#ifndef __aligned_u64
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif

#ifndef __struct_group
#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
	union { \
		struct { MEMBERS } ATTRS; \
		struct TAG { MEMBERS } ATTRS NAME; \
	} ATTRS
#endif

#ifndef __DECLARE_FLEX_ARRAY
#define __DECLARE_FLEX_ARRAY(TYPE, NAME) \
	struct { \
		struct { } __empty_ ## NAME; \
		TYPE NAME[]; \
	}
#endif

#ifndef __counted_by
#define __counted_by(m)
#endif

struct list_head {
	struct list_head *next, *prev;
};

#endif

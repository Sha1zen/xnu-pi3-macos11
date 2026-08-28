/*	$KAME: rijndael_local.h,v 1.5 2003/08/28 08:37:24 itojun Exp $	*/
/*	$FreeBSD$	*/

/*
 * Vendored verbatim from freebsd-src release/13.2.0
 * (sys/crypto/rijndael/rijndael_local.h) for xnu-on-rpi3's AES core
 * (docs/backlog.md item 0a). Only change from upstream: an explicit
 * <sys/types.h> include so this header is self-contained regardless of
 * caller include order (upstream relies on FreeBSD's own build always
 * having pulled sys/types.h in first).
 */
#include <sys/types.h>

/* the file should not be used from outside */
typedef uint8_t			u8;
typedef uint16_t		u16;
typedef uint32_t		u32;

/*
 * The wall clock.
 *
 * NOT part of the TLS binding, and kept in its own file so that
 * ffi/sekreto_curl.c stays the one place this port names an outside
 * library. This one names only libc.
 *
 * Lean 4.16 has `IO.monoMsNow` - a monotonic millisecond counter, which
 * is what token renewal wants - but no wall clock, and SigV4 signs a
 * `YYYYMMDDTHHMMSSZ` timestamp. So the seconds since the epoch come from
 * `time()`, and the civil date is computed in Lean, where it can be read
 * and tested: nothing about the calendar is delegated here.
 */

#include <lean/lean.h>

#include <time.h>

LEAN_EXPORT lean_obj_res sekreto_epoch_seconds(lean_obj_arg world) {
  (void)world;
  return lean_io_result_mk_ok(lean_box_uint64((uint64_t)time(NULL)));
}

/* No-op SanitizerCoverage hooks + app-provided wolfssl timers, so the
   sancov-instrumented vendored libwolfssl links into a stand-alone server. */
#include <stdint.h>
#include <time.h>
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) { (void)guard; }
void __sanitizer_cov_trace_pc_guard_init(uint32_t *s, uint32_t *e) { (void)s; (void)e; }
uint32_t LowResTimer(void) { return (uint32_t)time(NULL); }
int64_t TimeNowInMilliseconds(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
/* older vendored builds set "#define XTIME time_cb" (deterministic time for the
   fuzzer); supply a real-time implementation. Unused/harmless for other versions. */
time_t time_cb(time_t *t) { return time(t); }

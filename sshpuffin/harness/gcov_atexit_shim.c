/*
 * gcov_atexit_shim.c
 *
 * The clang gcov/profile runtime (libclang_rt.profile) calls atexit() to flush
 * .gcda counters at exit. glibc provides atexit() only in libc_nonshared.a,
 * which rust's `-nodefaultlibs` link suppresses — so a --features gcov build
 * fails with "undefined reference to atexit". Provide atexit() directly here by
 * forwarding to __cxa_atexit (present in libc.so), so the gcov build links.
 * Only compiled/linked for the gcov feature (see sshpuffin/build.rs).
 */
extern int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);
extern void *__dso_handle;

int atexit(void (*func)(void)) {
    return __cxa_atexit((void (*)(void *))func, (void *)0, __dso_handle);
}

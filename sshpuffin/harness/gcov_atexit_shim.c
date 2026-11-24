/*
 * gcov_atexit_shim.c
 *
 * The clang profile runtime of gcov and llvm_cov (libclang_rt.profile) calls
 * atexit() to write its counters (.gcda, .profraw) at exit. glibc provides
 * atexit() only in libc_nonshared.a, which rust's `-nodefaultlibs` link
 * suppresses — so a build that links a gcov or llvm_cov library fails with
 * "undefined reference to atexit". Provide atexit() directly here by forwarding
 * to __cxa_atexit (present in libc.so), so the build links. Compiled and linked
 * when a PUT's library has gcov or llvm_cov (see sshpuffin/build.rs).
 */
extern int __cxa_atexit(void (*func)(void *), void *arg, void *dso_handle);
extern void *__dso_handle;

/* Calling a function through a pointer of another type is undefined: __cxa_atexit
 * calls this one, with the type it expects, which calls the registered function. */
static void call_registered_function(void *func)
{
    ((void (*)(void))func)();
}

int atexit(void (*func)(void))
{
    return __cxa_atexit(call_registered_function, (void *)func, __dso_handle);
}

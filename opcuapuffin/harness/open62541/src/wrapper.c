#include "wrapper.h"

// Wrapper for `vsnprintf()` with normalized behavior across different platforms
// such as Microsoft Windows.
//
// Other than the standard `vsnprintf()`, this function does not consume the
// passed `va_list` argument! The caller is responsible for calling
// `vsnprintf_va_end()` on the `va_list` argument eventually.
#if defined(_MSC_VER) && _MSC_VER < 1900
int RS_vsnprintf_va_copy(
    char *buffer,
    size_t count,
    const char *format,
    va_list args)
{
  // Microsoft does not (always) define a standard-conforming `vsnprintf()`. But
  // it does define a variant with slightly different behavior. We normalize the
  // differences as best we can.
  int result = -1;
  if (count)
  {
    va_list args_copied;
    va_copy(args_copied, args);
    result = _vsnprintf_s(buffer, count, _TRUNCATE, format, args_copied);
  }
  if (result < 0)
  {
    va_list args_copied;
    va_copy(args_copied, args);
    result = _vscprintf(format, args_copied);
  }

  return result;
}
#else
int RS_vsnprintf_va_copy(
    char *buffer,
    size_t count,
    const char *format,
    va_list args)
{
  // Forward to existing standards-compliant function. It may have be defined as
  // a macro, so we need a wrapper function for bindgen to pick it up anyway.
  va_list args_copied;
  va_copy(args_copied, args);
  int result = vsnprintf(buffer, count, format, args_copied);

  return result;
}
#endif

void RS_vsnprintf_va_end(va_list args)
{
  va_end(args);
}

// bindgen does not support non-trivial `#define` used for pointer constant. Use
// statically defined constant as workaround for now.
//
// See https://github.com/rust-lang/rust-bindgen/issues/2426
const void *const RS_UA_EMPTY_ARRAY_SENTINEL = UA_EMPTY_ARRAY_SENTINEL;

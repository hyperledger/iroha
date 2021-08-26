/// Taken from
///   https://www.fluentcpp.com/2019/08/30/how-to-disable-a-warning-in-cpp/
///

#if defined(_MSC_VER)

# define DISABLE_WARNING_PUSH __pragma(warning(push))
# define DISABLE_WARNING_POP __pragma(warning(pop))
# define DISABLE_WARNING(warningNumber) \
  __pragma(warning(disable : warningNumber))

# define DISABLE_WARNING_unused_parameter \
  DISABLE_WARNING(4100)  // UNREFERENCED_FORMAL_PARAMETER
# define DISABLE_WARNING_unused_function \
  DISABLE_WARNING(4505)                             // UNREFERENCED_FUNCTION
# define DISABLE_WARNING_uninitialized               // TODO
# define DISABLE_WARNING_maybe_uninitialized         // TODO
# define DISABLE_WARNING_missing_field_initializers  // TODO

#elif defined(__GNUC__) || defined(__clang__)  // Apple Clang defines both

# define DO_PRAGMA(X) _Pragma(#X)

# define DISABLE_WARNING_PUSH DO_PRAGMA(GCC diagnostic push)
# define DISABLE_WARNING_POP DO_PRAGMA(GCC diagnostic pop)
# define DISABLE_WARNING(warningName)               \
  DO_PRAGMA(GCC diagnostic ignored #warningName)

// clang-format off
# define DISABLE_WARNING_unused_parameter DISABLE_WARNING(-Wunused-parameter)
# define DISABLE_WARNING_unused_function DISABLE_WARNING(-Wunused-function)
# define DISABLE_WARNING_uninitialized DISABLE_WARNING(-Wuninitialized)
# define DISABLE_WARNING_missing_field_initializers DISABLE_WARNING(-Wmissing-field-initializers)
// clang-format on

# if defined(__clang__)
# define DISABLE_WARNING_maybe_uninitialized //ToDo
# elif defined(__GNUC__)
#  define DISABLE_WARNING_maybe_uninitialized DISABLE_WARNING(-Wmaybe-uninitialized)
# endif

#else

# define DISABLE_WARNING_PUSH
# define DISABLE_WARNING_POP
# define DISABLE_WARNING_unused_parameter
# define DISABLE_WARNING_unused_function
# define DISABLE_WARNING_uninitialized
# define DISABLE_WARNING_maybe_uninitialized
# define DISABLE_WARNING_missing_field_initializers

#endif

/* Stub file to force linking with libcapstone.
   ctypes-foreign uses dlsym(RTLD_DEFAULT, ...) which requires the library
   to be loaded. By calling a capstone function here, we ensure the
   linker includes libcapstone even with --as-needed. */

#include <capstone.h>
#include <caml/mlvalues.h>

/* Force linker to include capstone by actually calling a function.
   This is called during OCaml initialization. */
CAMLprim value capstone_force_link(value unit) {
    int major, minor;
    cs_version(&major, &minor);
    (void)major;
    (void)minor;
    return Val_unit;
}

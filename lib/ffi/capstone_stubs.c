/* Stub file to force linking with libcapstone.
   ctypes-foreign uses dlsym(RTLD_DEFAULT, ...) which requires the library
   to be loaded. By referencing a capstone symbol here, we ensure the
   linker includes libcapstone. */

#include <capstone.h>

/* Force linker to include capstone by referencing a symbol */
void *_capstone_force_link(void) {
    return (void *)cs_version;
}

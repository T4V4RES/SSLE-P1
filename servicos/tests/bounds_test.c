#include "ssle.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

int main(void) {
    assert(http_body_fits(0, 65536));
    assert(http_body_fits(65536, 0));
    assert(!http_body_fits(65536, 1));
    assert(!http_body_fits(SIZE_MAX, 1));
    assert(!http_body_fits(1, SIZE_MAX));
    setenv("SSLE_TEST_INT", "2147483648", 1);
    assert(env_int("SSLE_TEST_INT", 7) == 7);
    setenv("SSLE_TEST_INT", "99999999999999999999999999", 1);
    assert(env_int("SSLE_TEST_INT", 7) == 7);
    setenv("SSLE_TEST_INT", "2x", 1);
    assert(env_int("SSLE_TEST_INT", 7) == 7);
    setenv("SSLE_TEST_INT", "32", 1);
    assert(env_int("SSLE_TEST_INT", 7) == 32);
    return 0;
}

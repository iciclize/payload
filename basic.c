/*_
 * Copyright (c) 2016,2018 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "radix.h"
#include <stdio.h>
#include <sys/time.h>
#include <inttypes.h>

/*
 * Xorshift
 */
static __inline__ uint32_t
xor128(void)
{
    static uint32_t x = 123456789;
    static uint32_t y = 362436069;
    static uint32_t z = 521288629;
    static uint32_t w = 88675123;
    uint32_t t;

    t = x ^ (x<<11);
    x = y;
    y = z;
    z = w;
    return w = (w ^ (w>>19)) ^ (t ^ (t >> 8));
}

static int
test_lookup_linx_performance(void)
{
    struct radix_tree *rt;
    FILE *fp;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    int nexthop[4];
    int ret;
    uint8_t addr1[4];
    uint64_t addr2;
    ssize_t i;
    uint64_t res;
    double t0;
    double t1;
    uint32_t a;

    /* Load from the linx file */
    fp = fopen("tests/linx-rib.20141217.0000-p46.txt", "r");
    if ( NULL == fp ) {
        return -1;
    }

    /* Initialize */
    rt = radix_tree_init(NULL);
    if ( NULL == rt ) {
        return -1;
    }

    /* Load the full route */
    i = 0;
    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d.%d.%d.%d/%d %d.%d.%d.%d", &prefix[0], &prefix[1],
                     &prefix[2], &prefix[3], &prefixlen, &nexthop[0],
                     &nexthop[1], &nexthop[2], &nexthop[3]);
        if ( ret < 0 ) {
            return -1;
        }

        /* Convert to u32 */
        addr1[0] = prefix[0];
        addr1[1] = prefix[1];
        addr1[2] = prefix[2];
        addr1[3] = prefix[3];
        addr2 = ((uint32_t)nexthop[0] << 24) + ((uint32_t)nexthop[1] << 16)
            + ((uint32_t)nexthop[2] << 8) + (uint32_t)nexthop[3];

        /* Add an entry */
        ret = radix_tree_add(rt, addr1, prefixlen, (void *)(uint64_t)addr2);
        if ( ret < 0 ) {
            return -1;
        }
        if ( 0 == i % 10000 ) {
            TEST_PROGRESS();
        }
        i++;
    }

    t0 = getmicrotime();

    res = 0;
    for ( i = 0; i < 0x100000000LL; i++ ) {
        if ( 0 == i % 0x10000000ULL ) {
            TEST_PROGRESS();
        }
        a = xor128();
        res ^= (uint64_t)radix_tree_lookup(rt, (uint8_t *)&a);
    }

    /* Release */
    radix_tree_release(rt);

    /* Close */
    fclose(fp);

    return 0;
}

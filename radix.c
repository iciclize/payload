/*_
 * Copyright (c) 2016-2017 Hirochika Asai <asai@jar.jp>
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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "radix.h"

#define BIT_TEST(k, b)  (((uint8_t *)(k))[(b) >> 3] & (0x80 >> ((b) & 0x7)))

/*
 * Initialize the data structure for radix tree
 */
struct radix_tree *
radix_tree_init(struct radix_tree *rt)
{
    if ( NULL == rt ) {
        /* Allocate new data structure */
        rt = malloc(sizeof(struct radix_tree));
        if ( NULL == rt ) {
            return NULL;
        }
        rt->_allocated = 1;
    } else {
        rt->_allocated = 0;
    }

    /* Set NULL to the root node */
    rt->root = NULL;

    return rt;
}

/*
 * Release the node and descendant nodes
 */
static void
_free_nodes(struct radix_tree_node *node)
{
    if ( NULL != node ) {
        _free_nodes(node->left);
        _free_nodes(node->right);
        free(node);
    }
}

/*
 * Release the radix tree
 */
void
radix_tree_release(struct radix_tree *rt)
{
    _free_nodes(rt->root);
    if ( rt->_allocated ) {
        free(rt);
    }
}

/*
 * Recursive process of the lookup procedure
 */
static void *
_lookup(struct radix_tree_node *cur, struct radix_tree_node *cand, uint8_t *key,
        int depth)
{
    if ( NULL == cur ) {
        /* Return the candidate node as the longest prefix matching node */
        return NULL != cand ? cand->data : NULL;
    }

    if ( cur->valid ) {
        /* Update the candidate return value (longest prefix matching) */
        cand = cur;
    }

    /* Check the corresponding bit */
    if ( BIT_TEST(key, depth) ) {
        /* Right node */
        return _lookup(cur->right, cand, key, depth + 1);
    } else {
        /* Left node */
        return _lookup(cur->left, cand, key, depth + 1);
    }
}

/*
 * Lookup the data corresponding to the key specified by the argument
 */
void *
radix_tree_lookup(struct radix_tree *rt, uint8_t *key)
{
    return _lookup(rt->root, NULL, key, 0);
}

/*
 * Add a data value (recursive)
 */
static int
_add(struct radix_tree_node **cur, uint8_t *key, int prefixlen, void *data,
     int depth)
{
    struct radix_tree_node *new;

    /* Allocate a new node */
    if ( NULL == *cur ) {
        new = malloc(sizeof(struct radix_tree_node));
        if ( NULL == new ) {
            return -1;
        }
        memset(new, 0, sizeof(struct radix_tree_node));
        *cur = new;
    }

    if ( prefixlen == depth ) {
        /* The current node is the point to add the data */
        if ( (*cur)->valid ) {
            /* Already exists */
            return -1;
        }
        (*cur)->valid = 1;
        (*cur)->data = data;
        return 0;
    } else {
        /* Check the corresponding bit */
        if ( BIT_TEST(key, depth) ) {
            /* Right node */
            return _add(&(*cur)->right, key, prefixlen, data, depth + 1);
        } else {
            /* Left node */
            return _add(&(*cur)->left, key, prefixlen, data, depth + 1);
        }
    }
}

/*
 * Add a data value to the key
 */
int
radix_tree_add(struct radix_tree *rt, uint8_t *key, int prefixlen, void *data)
{
    return _add(&rt->root, key, prefixlen, data, 0);
}

/*
 * Shrink the tree
 */
static int
_shrink(struct radix_tree_node **cur)
{
    int lret;
    int rret;

    if ( NULL == *cur ) {
        /* Parent could be deleted if the sibling is deletable. */
        return 0;
    }

    lret = _shrink(&(*cur)->left);
    rret = _shrink(&(*cur)->right);

    if ( lret || rret ) {
        /* Cannot delete this node because the children are not deleted */
        return 1;
    } else {
        /* Check if this node is ready to delete (no children exists and not
           valid) */
        if ( NULL == (*cur)->left && NULL == (*cur)->right && !(*cur)->valid ) {
            free(*cur);
            *cur = NULL;
            return 0;
        } else {
            return 1;
        }
    }
}

/*
 * Delete (recursive)
 */
static void *
_delete(struct radix_tree_node **cur, uint8_t *key, int prefixlen, int depth)
{
    void *data;

    /* Allocate a new node */
    if ( NULL == *cur ) {
        /* Not found */
        return NULL;
    }

    if ( prefixlen == depth ) {
        /* The current node is the point to add the data */
        if ( (*cur)->valid ) {
            /* Found */
            data = (*cur)->data;
            /* Try to shrink the tree */
            (*cur)->valid = 0;
            (*cur)->data = 0;
            _shrink(cur);
            return data;
        } else {
            /* Not found */
            return NULL;
        }
    } else {
        /* Check the corresponding bit */
        if ( BIT_TEST(key, depth) ) {
            /* Right node */
            return _delete(&(*cur)->right, key, prefixlen, depth + 1);
        } else {
            /* Left node */
            return _delete(&(*cur)->left, key, prefixlen, depth + 1);
        }
    }
}

/*
 * Delete the data value corresponding to the key and return it
 */
void *
radix_tree_delete(struct radix_tree *rt, uint8_t *key, int prefixlen)
{
    return _delete(&rt->root, key, prefixlen, 0);
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */

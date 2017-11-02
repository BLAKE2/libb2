#include "blake2.h"
#include "blake2-impl.h"

#include <string.h>

void blake2b_param_init(blake2b_param * P) {
    memset(P->bytes, 0, sizeof(P->bytes));
}

int blake2b_param_set_digest_length(blake2b_param * P, size_t outlen) {
    if(outlen < 1 || outlen > BLAKE2B_OUTBYTES) {
        return -1;
    }
    P->bytes[0] = outlen & 0xFF;
    return 0;
}

int blake2b_param_set_key_length(blake2b_param * P, size_t keylen) {
    if(keylen > BLAKE2B_OUTBYTES) {
        return -1;
    }
    P->bytes[1] = keylen & 0xFF;
    return 0;
}

int blake2b_param_set_fanout(blake2b_param * P, size_t fanout) {
    if(fanout > 255) {
        return -1;
    }
    P->bytes[2] = fanout & 0xFF;
    return 0;
}

int blake2b_param_set_depth(blake2b_param * P, size_t depth) {
    if(depth < 1 || depth > 255) {
        return -1;
    }
    P->bytes[3] = depth & 0xFF;
    return 0;
}

int blake2b_param_set_leaf_length(blake2b_param * P, uint32_t leaf_length) {
    store32(&P->bytes[4], leaf_length);
    return 0;
}

int blake2b_param_set_node_offset(blake2b_param * P, uint64_t node_offset) {
    store64(&P->bytes[8], node_offset);
    return 0;
}

int blake2b_param_set_node_depth(blake2b_param * P, size_t node_depth) {
    if(node_depth > 255) {
        return -1;
    }
    P->bytes[16] = node_depth & 0xFF;
    return 0;
}

int blake2b_param_set_inner_length(blake2b_param * P, size_t inner_length) {
    if(inner_length > BLAKE2B_OUTBYTES) {
        return -1;
    }
    P->bytes[17] = inner_length & 0xFF;
    return 0;
}

int blake2b_param_set_salt(blake2b_param * P, const uint8_t salt[BLAKE2B_SALTBYTES]) {
    memcpy(&P->bytes[32], salt, BLAKE2B_SALTBYTES);
    return 0;
}

int blake2b_param_set_personal(blake2b_param * P, const uint8_t personal[BLAKE2B_PERSONALBYTES]) {
    memcpy(&P->bytes[48], personal, BLAKE2B_PERSONALBYTES);
    return 0;
}


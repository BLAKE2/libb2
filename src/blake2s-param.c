#include "blake2.h"
#include "blake2-impl.h"

#include <string.h>

void blake2s_param_init(blake2s_param * P) {
    memset(P->bytes, 0, sizeof(P->bytes));
}

int blake2s_param_set_digest_length(blake2s_param * P, size_t outlen) {
    if(outlen < 1 || outlen > BLAKE2S_OUTBYTES) {
        return -1;
    }
    P->bytes[0] = outlen & 0xFF;
    return 0;
}

int blake2s_param_set_key_length(blake2s_param * P, size_t keylen) {
    if(keylen > BLAKE2S_OUTBYTES) {
        return -1;
    }
    P->bytes[1] = keylen & 0xFF;
    return 0;
}

int blake2s_param_set_fanout(blake2s_param * P, size_t fanout) {
    if(fanout > 255) {
        return -1;
    }
    P->bytes[2] = fanout & 0xFF;
    return 0;
}

int blake2s_param_set_depth(blake2s_param * P, size_t depth) {
    if(depth < 1 || depth > 255) {
        return -1;
    }
    P->bytes[3] = depth & 0xFF;
    return 0;
}

int blake2s_param_set_leaf_length(blake2s_param * P, uint32_t leaf_length) {
    store32(&P->bytes[4], leaf_length);
    return 0;
}

int blake2s_param_set_node_offset(blake2s_param * P, uint64_t node_offset) {
    if(node_offset > ((1ULL << 48) - 1)) {
        return -1;
    }
    store48(&P->bytes[8], node_offset);
    return 0;
}

int blake2s_param_set_node_depth(blake2s_param * P, size_t node_depth) {
    if(node_depth > 255) {
        return -1;
    }
    P->bytes[14] = node_depth & 0xFF;
    return 0;
}

int blake2s_param_set_inner_length(blake2s_param * P, size_t inner_length) {
    if(inner_length > BLAKE2S_OUTBYTES) {
        return -1;
    }
    P->bytes[15] = inner_length & 0xFF;
    return 0;
}

int blake2s_param_set_salt(blake2s_param * P, const uint8_t salt[BLAKE2S_SALTBYTES]) {
    memcpy(&P->bytes[16], salt, BLAKE2S_SALTBYTES);
    return 0;
}

int blake2s_param_set_personal(blake2s_param * P, const uint8_t personal[BLAKE2S_PERSONALBYTES]) {
    memcpy(&P->bytes[24], personal, BLAKE2S_PERSONALBYTES);
    return 0;
}


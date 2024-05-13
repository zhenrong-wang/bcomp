/**
 * Copyright (C) 2022-present Zhenrong WANG
 *   -> https://github.com/zhenrong-wang
 *   -> X/Twitter: @wangzhr4
 * This code is distributed under the license: MIT License
 * Originally written by Zhenrong WANG
 * mailto: zhenrongwang@live.com 
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FLIP_BIT_TO_1(byte,n) ((byte) |= ((0x80) >> (n))) 
#define FLIP_BIT_TO_0(byte,n) ((byte) &= ((0x7F) >> (n)))
#define GET_MAX(a,b) (((a) > (b)) ? a : b)
#define GET_MIN(a,b) (((a) < (b)) ? a : b)

#define FULL_STATE_BYTES 256

struct freq_matrix {
    uint8_t index;
    uint16_t freq;
};

struct bcomp_byte {
    uint8_t byte_high_value;
    uint8_t suffix_bits;
};

struct bcomp_state {
    uint8_t  bytes[257];
    uint16_t curr_byte;
    uint8_t  curr_bits_suffix;
    uint16_t  total_bits_suffix;
};

struct decomp_state {
    const uint8_t *bytes_head;
    uint16_t curr_byte;
    uint8_t curr_bits_offset;
};

int compare(const void *a, const void *b) {  
    struct freq_matrix *ptr_a = (struct freq_matrix *)a;
    struct freq_matrix *ptr_b = (struct freq_matrix *)b;
    return ptr_b->freq - ptr_a->freq;
}

int16_t is_top_freq(const struct freq_matrix *frequency, const uint8_t start, const uint8_t end, const uint8_t byte) {
    for(uint8_t i = start; i < end; i++) {
        if(byte == frequency[i].index) {
            return i;
        }
    }
    return -1;
}

int get_next_bits(struct decomp_state *decomp_state, const uint8_t num_of_bits, uint8_t *res) {
    if(decomp_state == NULL || decomp_state->bytes_head ==NULL || res == NULL) {
        return -1;
    }
    if(num_of_bits > 8) {
        return -3;
    }
    *res = 0x00;
    uint8_t initial = 0xFF;
    uint8_t this_byte = decomp_state->bytes_head[decomp_state->curr_byte];
    uint8_t bit_offs = decomp_state->curr_bits_offset;

    if((bit_offs + num_of_bits) < 8) {
        *res = ((initial >> (bit_offs + 1)) & this_byte) >> (7 - bit_offs - num_of_bits);
        decomp_state->curr_bits_offset += num_of_bits;
    }
    else {
        uint8_t next_byte = decomp_state->bytes_head[decomp_state->curr_byte + 1];
        uint8_t next_byte_bits = num_of_bits + bit_offs - 7;
        *res = (((initial >> (bit_offs + 1)) & this_byte) << next_byte_bits) | (next_byte >> (8-next_byte_bits));
        decomp_state->curr_byte++;
        decomp_state->curr_bits_offset = bit_offs + num_of_bits - 8;
    }
    return 0;
}

int append_comp_byte(struct bcomp_state *comp_state, uint8_t byte, uint8_t high_bits) {
    if(comp_state == NULL) {
        return -1;
    }
    comp_state->total_bits_suffix -= high_bits;
    if(comp_state->curr_bits_suffix == 0) {
        comp_state->curr_byte++;
        comp_state->bytes[comp_state->curr_byte] = byte;
        comp_state->curr_bits_suffix = 8 - high_bits;
        return 0;
    }

    if(comp_state->curr_bits_suffix >= high_bits) {
        comp_state->bytes[comp_state->curr_byte] |= (byte >> (8 - comp_state->curr_bits_suffix));
        comp_state->curr_bits_suffix -= high_bits;
    }
    else {
        comp_state->bytes[comp_state->curr_byte] |= (byte >> (8 - comp_state->curr_bits_suffix));
        comp_state->curr_byte++;
        comp_state->bytes[comp_state->curr_byte] |= (byte << comp_state->curr_bits_suffix);
        comp_state->curr_bits_suffix += (8 - high_bits);
    }
    return 0;
}

/* The bcomp_state must have at least 258 bytes. */
int8_t compress_core(const uint8_t state[], const uint16_t raw_bytes, struct bcomp_state *comp_state, uint16_t *bcomp_bits) {
    if(state == NULL || comp_state == NULL || bcomp_bits == NULL) {
        return -1;
    }
    if(raw_bytes == 0 || raw_bytes > FULL_STATE_BYTES) {
        return -3;
    }
    uint16_t raw_bits = raw_bytes * 8;
    struct freq_matrix frequency[256];
    uint16_t top2_freqs = 0, top4_freqs = 0, top6_freqs = 0, top2_6_freqs = 0;
    uint8_t index_max_2 = 0, index_max_4 = 0, index_max_6 = 0;
    uint8_t dict_elem_flags[4] = {0,};
    uint16_t comp_bits[4] = {0,}, comp_bits_min = 0;
    uint8_t comp_method = 0, dict_elem_code = 0;
    const uint8_t num_dict_elems[4] = {2, 4, 6, 6};
    const uint8_t dict_elem_size[4][3] = {
        1, 4, 8,
        2, 4, 8,
        3, 6, 8,
        3, 6, 8
    };
    const uint8_t dict_total_size[4][3] = {
        2,  8,  16,
        8,  16, 32,
        18, 36, 48,
        18, 36, 48
    };

    /* 0xFF is illegal. */
    const uint8_t comp_byte_size[4] = {1, 2, 0xFF, 3};

    uint16_t i = 0;
    uint8_t header = 0x00;

    *bcomp_bits = raw_bytes * 8 + 1;

    memset(comp_state->bytes, 0, 257 * sizeof(uint8_t));
    comp_state->curr_bits_suffix = 8;
    comp_state->curr_byte = 0;
    comp_state->total_bits_suffix = 2056;

    for(i = 0; i < 256; i++) {
        frequency[i].index = i;
        frequency[i].freq = 0;
    }
    for(i = 0; i < raw_bytes; i++) {
        frequency[state[i]].freq++;
    }
    qsort(frequency, 256, sizeof(struct freq_matrix), compare);

    top2_freqs = frequency[0].freq + frequency[1].freq;
    top4_freqs = top2_freqs + frequency[2].freq + frequency[3].freq;
    top6_freqs = top4_freqs + frequency[4].freq + frequency[5].freq;
    top2_6_freqs = top6_freqs - top2_freqs;
    
    index_max_2 = GET_MAX(frequency[0].index, frequency[1].index);
    index_max_4 = GET_MAX(GET_MAX(frequency[2].index, frequency[3].index), index_max_2);
    index_max_6 = GET_MAX(GET_MAX(frequency[4].index, frequency[5].index), index_max_4);
    //printf("index_max: %x %x %x\t::::::::::::::\n", index_max_2, index_max_4, index_max_6);

    if(index_max_2 < 0x02) {
        dict_elem_flags[0] = 0;
    }
    else if(index_max_2 < 0x10) {
        dict_elem_flags[0] = 1;
    }
    else {
        dict_elem_flags[0] = 2;
    }

    if(index_max_4 < 0x04) {
        dict_elem_flags[1] = 0;
    }
    else if(index_max_4 < 0x10) {
        dict_elem_flags[1] = 1;
    }
    else {
        dict_elem_flags[1] = 2;
    }

    if(index_max_6 < 8) {
        dict_elem_flags[2] = 0;
        dict_elem_flags[3] = 0;
    }
    else if(index_max_6 < 0x40) {
        dict_elem_flags[2] = 1;
        dict_elem_flags[3] = 1;
    }
    else {
        dict_elem_flags[2] = 2;
        dict_elem_flags[3] = 2;
    }

    //printf("%d\t%d\t%d\t%d\t\t%d\n", top2_freqs, top4_freqs, top6_freqs, top2_6_freqs, dict_elem_flags[0]);

    comp_bits[0] = 5 + dict_total_size[0][dict_elem_flags[0]] + top2_freqs * 2 + (raw_bytes - top2_freqs) + (raw_bytes - top2_freqs) * 8;
    comp_bits[1] = 5 + dict_total_size[1][dict_elem_flags[1]] + top4_freqs * 3 + (raw_bytes - top4_freqs) + (raw_bytes - top4_freqs) * 8;
    comp_bits[2] = 5 + dict_total_size[2][dict_elem_flags[2]] + top2_freqs * 3 + top2_6_freqs *4 + (raw_bytes - top6_freqs) + (raw_bytes - top6_freqs) * 8;
    comp_bits[3] = 5 + dict_total_size[3][dict_elem_flags[3]] + top6_freqs * 4 + (raw_bytes - top6_freqs) + (raw_bytes - top6_freqs) * 8;

    //printf("%d\t%d\t%d\t%d\n", comp_bits[0], comp_bits[1], comp_bits[2], comp_bits[3]);

    if(comp_bits[0] >= raw_bits && comp_bits[1] >= raw_bits && comp_bits[2] >= raw_bits && comp_bits[3] >= raw_bits) {
        header = 0x00;
        append_comp_byte(comp_state, header, 1);
        for(i = 0; i < raw_bytes; i++) {
            append_comp_byte(comp_state, state[i], 8);
        }
        if(raw_bytes != FULL_STATE_BYTES) {
            append_comp_byte(comp_state, (uint8_t)raw_bytes, 8);
        }
        return 0;
    }

    comp_bits_min = comp_bits[0];
    dict_elem_code = dict_elem_flags[0];
    for(i = 1; i < 4; i++) {
        if(comp_bits[i] < comp_bits_min) {
            comp_bits_min = comp_bits[i];
            comp_method = i;
            dict_elem_code = dict_elem_flags[i];
        }
    }
    
    *bcomp_bits = comp_bits_min;
    header = (0x80) | (comp_method << 5) | (dict_elem_code << 3);
    /* Paddle the header */
    append_comp_byte(comp_state, header, 5);
    uint8_t dict_elem_bits = dict_elem_size[comp_method][dict_elem_code];
    uint8_t dict_elem_left = 8 - dict_elem_bits;
    uint8_t freq_pos = 0;
    uint8_t compressed_byte;
    /* Paddle the dictionary */
    for(i = 0; i < num_dict_elems[comp_method]; i++) {
        append_comp_byte(comp_state, frequency[i].index << dict_elem_left, dict_elem_bits);
    }
    for(i = 0; i < raw_bytes; i++) {
        freq_pos = is_top_freq(frequency, 0, num_dict_elems[comp_method], state[i]);
        if(freq_pos < 0) {
            /* Uncompressed byte. 0 xxxxxxxx */
            append_comp_byte(comp_state, (uint8_t)0x00, 1);
            append_comp_byte(comp_state, state[i], 8);
        }
        else {
            /* For method C, we need special operations. */
            if(comp_method == 2) {
                if(freq_pos < 2) {
                    append_comp_byte(comp_state, (uint8_t)0x80, 2);
                    compressed_byte = freq_pos << 7;
                    append_comp_byte(comp_state, compressed_byte, 1);
                }
                else {
                    append_comp_byte(comp_state, (uint8_t)0xC0, 2);
                    compressed_byte = (freq_pos - 2) << 6;
                    append_comp_byte(comp_state, compressed_byte, 2);
                }
            }
            else {
                append_comp_byte(comp_state, (uint8_t)0x80, 1);
                compressed_byte = freq_pos << (8 - comp_byte_size[comp_method]);
                append_comp_byte(comp_state, compressed_byte, comp_byte_size[comp_method]);
            }
        }
    }
    if(raw_bytes != FULL_STATE_BYTES) {
        append_comp_byte(comp_state, (uint8_t)raw_bytes, 8);
    }
    return 1;
}

int decompression_core(const uint8_t *decomp_state_head, const uint16_t orig_bytes, const uint8_t bit_offset, uint8_t state[]){
    if(decomp_state_head == NULL || bit_offset > 7 || state == NULL || orig_bytes > FULL_STATE_BYTES) {
        return -1;
    }
    uint16_t i = 0;
    if(((*decomp_state_head) & (0x80 >> bit_offset)) == 0) {
        for(i = 0; i < orig_bytes; i++) {
            state[i] = decomp_state_head[i] << (bit_offset + 1) | decomp_state_head[i+1] >> (7 - bit_offset);
        }
        return 0;
    }
    const uint8_t num_dict_elems[4] = {2, 4, 6, 6};
    const uint8_t dict_elem_size[4][3] = {
        1, 4, 8,
        2, 4, 8,
        3, 6, 8,
        3, 6, 8
    };
    const uint8_t dict_total_size[4][3] = {
        2,  8,  16,
        8,  16, 32,
        18, 36, 48,
        18, 36, 48
    };

    const uint8_t comp_byte_size[4] = {1, 2, 0xFF, 3};
    uint8_t dict_elems[6] = {0x00,};
    uint8_t dict_elem_index = 0;
    uint8_t byte_comp_flag = 0;
    uint8_t comp_method = 0, dict_elem_code = 0;
    
    struct decomp_state decom_state;
    decom_state.bytes_head = decomp_state_head;
    decom_state.curr_byte = 0;
    decom_state.curr_bits_offset = bit_offset;

    if(get_next_bits(&decom_state, 2, &comp_method) < 0) {
        return -3;
    }
    if(get_next_bits(&decom_state, 2, &dict_elem_code) < 0) {
        return -3;
    }
    
    for( i = 0; i < num_dict_elems[comp_method]; i++) {
        if(get_next_bits(&decom_state, dict_elem_size[comp_method][dict_elem_code], dict_elems + i) < 0) {
            return -3;
        }
    }

    for(i = 0; i < orig_bytes; i++){
        if(get_next_bits(&decom_state, 1, &byte_comp_flag) < 0) {
            return -3;
        }
        if(byte_comp_flag == 0) {
            if(get_next_bits(&decom_state, 8, state + i) < 0) {
                return -3;
            }
        }
        else {
            if(comp_method == 2) {
                if(get_next_bits(&decom_state, 1, &byte_comp_flag) < 0) {
                    return -3;
                }
                if(byte_comp_flag == 0) {
                    if(get_next_bits(&decom_state, 1, &dict_elem_index) < 0) {
                        return -3;
                    }
                }
                else {
                    if(get_next_bits(&decom_state, 2, &dict_elem_index) < 0) {
                        return -3;
                    }
                    dict_elem_index += 2;
                }
                state[i] = dict_elems[dict_elem_index];
            }
            else {
                if(get_next_bits(&decom_state, comp_byte_size[comp_method], &dict_elem_index) < 0) {
                    return -3;
                }
                state[i] = dict_elems[dict_elem_index];
            }
        }
    }
    return 0;
}

#if defined fuzz && fuzz == 1

#define crash(x) do{ if(!(x)){ int volatile* volatile ptr; ptr = 0; *ptr = 0; } }while(0)

void fuzz_1(unsigned char const* const data, size_t const size)
{
    uint8_t state[256];
    struct bcomp_state state_out;
    uint16_t bcomp_bits;
    uint8_t decompressed[256];

    if(!(size >= 256)){ return; }
    memcpy(&state[0], data, 256);
    compress_core(&state[0], 256, &state_out, &bcomp_bits);
    decompression_core(&state_out.bytes[0], 256, 0, &decompressed[0]);
    crash(memcmp(&decompressed[0], &state[0], 256) == 0);
}

void fuzz_2(unsigned char const* const data, size_t const size)
{
    struct bcomp_state state;
    uint8_t decompressed[256];

    if(!(size >= sizeof(state))){ return; }
    memcpy(&state, data, sizeof(state));
    decompression_core(&state.bytes[0], 256, 0, &decompressed[0]);
}

int LLVMFuzzerTestOneInput(unsigned char const* const data, size_t const size)
{
    fuzz_1(data, size);
    fuzz_2(data, size);
    return 0;
}

#else

int main(int argc, char **argv) {
    uint8_t state[256] = {0x00,};
    uint8_t decompressed[256] = {0x00,};
    uint16_t i;
    for(i = 0; i < 256; i++) {
        state[i] = i % 6 + 20;
    }
    printf("INPUT: %d bits\n", 2048);
    for(i = 0; i < 256; i++) {
        printf("%x ", state[i]);
    }
    putchar('\n');
    putchar('\n');
    uint16_t bcomp_bits = 0;
    struct bcomp_state state_out;

    compress_core(state, 256, &state_out, &bcomp_bits);

    printf("COMPRESSED: %d bits\n", bcomp_bits);
    for(i = 0; i < 257; i++) {
        printf("%x ", state_out.bytes[i]);
    }
    putchar('\n');
    putchar('\n');

    decompression_core(state_out.bytes, 256, 0, decompressed);

    printf("DECOMPRESSED\n");
    for(i = 0; i < 256; i++) {
        printf("%x ", decompressed[i]);
    }
    putchar('\n');
    return 0;
}

#endif

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

#define FREQUENCY_TABLE_SIZE    256
#define FULL_STATE_BYTES        256
#define DECOMP_INGEST_BYTES     1024
#define COMP_METHOD_MAX         6
#define DICT_ELEM_CODE_MAX_A    4  
#define DICT_ELEM_CODE_MAX_BCD  3
#define INVALID_HEADER_FLAG     127
#define INVALID_FILE_TO_DECOMP  123
#define FILE_IO_ERROR           121
#define INVALID_DATA_TO_DECOMP  119
#define BLOCK_MAX_STATE_NUM     8
#define FULL_BLOCK_BYTES        (FULL_STATE_BYTES * BLOCK_MAX_STATE_NUM)

struct freq_matrix {
    uint8_t index;
    uint32_t freq;
};

struct bcomp_byte {
    uint8_t byte_high_value;
    uint8_t suffix_bits;
};

/*struct bcomp_obuffer {
    uint8_t bytes_array[257];
    uint16_t bytes_valid;
    uint8_t prev_tail;
    uint8_t prev_tail_high_bits;
    uint8_t io_end;
};*/

/*struct bcomp_state {
    uint8_t  bytes[257];
    uint16_t curr_byte;
    uint8_t  curr_bits_suffix;
    uint16_t  total_bits;
    uint8_t io_end;
};*/

struct bcomp_obuffer_block {
    uint8_t bytes_array_block[FULL_BLOCK_BYTES + 1];
    uint16_t bytes_valid;
    uint8_t prev_tail;
    uint8_t prev_tail_high_bits;
    uint8_t io_end;
};

struct bcomp_state_block {
    uint8_t  bytes_block[FULL_BLOCK_BYTES + 1];
    uint16_t curr_byte;
    uint8_t  curr_bits_suffix;
    uint16_t  total_bits;
    uint8_t io_end;
};

struct decomp_state {
    uint8_t *bytes_head;
    uint64_t curr_byte;
    uint8_t curr_bits_offset;
    uint64_t stream_bytes_curr;
    uint64_t stream_bytes_total;
};

struct block_comp_option {
    uint8_t block_comp_flag;
    uint8_t block_incomp_size;
    uint8_t block_incomp_min;
    uint8_t block_incomp_min_size;
    uint8_t num_raw_states;
    uint16_t num_raw_bytes;
    uint8_t block_comp_method;
    uint8_t dict_elem_code;
    uint8_t dict_elem_table[64];
    uint8_t dict_elem_bits;
    uint8_t num_dict_elems;
    uint8_t comp_byte_size;
    uint8_t comp_incomp_min;
    uint8_t comp_incomp_flag;
    uint8_t comp_incomp_bits;
    float comp_ratio;
};

int compare(const void *a, const void *b) {  
    struct freq_matrix *ptr_a = (struct freq_matrix *)a;
    struct freq_matrix *ptr_b = (struct freq_matrix *)b;
    return ptr_b->freq - ptr_a->freq;
}

int8_t is_in_dict(const uint8_t dict_table[], const uint8_t start, const uint8_t end, const uint8_t num_dict_elems_max, const uint8_t byte) {
    if(dict_table == NULL) {
        return -3;
    }
    for(uint8_t i = start; i < end && i < num_dict_elems_max; i++) {
        if(byte == dict_table[i]) {
            return i;
        }
    }
    return -1;
}

int8_t decomp_read_end(const int64_t file_size, const uint8_t tail_byte, const struct decomp_state decom_state) {
    int64_t byte_pos = (int64_t)decom_state.stream_bytes_curr + (int64_t)decom_state.curr_byte;
    if(byte_pos < file_size - 2) {
        return 0;
    }
    if(byte_pos > file_size - 2) {
        return 1;
    }
    if(tail_byte == 0x00) {
        return 0;
    }
    if(decom_state.curr_bits_offset < tail_byte) {
        return 0;
    }
    return 1;
}

int get_next_bits(uint8_t buffer[], const uint64_t buffer_size_byte, const uint8_t num_of_bits, uint8_t *res, struct decomp_state *decom_state, FILE *stream) {
    if(stream == NULL || res == NULL || decom_state == NULL) {
        return -1;
    }
    if(num_of_bits > 8 || num_of_bits == 0) {
        return -3;
    }
    if(buffer_size_byte < 1) {
        return -5;
    }
    *res = 0x00;
    size_t bytes_read = 0;
    
    /* If the bytes_head == NULL, we need to initiate the state. */
    if(decom_state->bytes_head == NULL) {
        decom_state->bytes_head = buffer;
        bytes_read = fread(buffer, sizeof(uint8_t), buffer_size_byte, stream);
        if(bytes_read == 0) {
            return -7;
        }
        decom_state->stream_bytes_total += bytes_read;
        decom_state->stream_bytes_curr = 0;
        decom_state->curr_bits_offset = 0;
        decom_state->curr_byte = 0;
    }

    uint8_t initial = 0xFF;
    uint8_t this_byte = buffer[decom_state->curr_byte];
    uint8_t bit_offs = decom_state->curr_bits_offset;
    uint8_t next_byte = 0;
    uint8_t next_byte_bits = 0;

    if((bit_offs + num_of_bits) >=8 && decom_state->curr_byte == (buffer_size_byte - 1)) {
        bytes_read = fread(buffer, sizeof(uint8_t), buffer_size_byte, stream);
        if(bytes_read == 0) {
            return -9;
        }
        next_byte_bits = (num_of_bits + bit_offs) % 8;
        next_byte = buffer[0];
        *res = (((initial >> bit_offs) & this_byte) << next_byte_bits) | (next_byte >> (8 - next_byte_bits));
        decom_state->curr_byte = 0;
        decom_state->curr_bits_offset = next_byte_bits;
        decom_state->stream_bytes_curr += buffer_size_byte;
        decom_state->stream_bytes_total += bytes_read;
        return 0;
    }

    if((bit_offs + num_of_bits) < 8) {
        *res = ((initial >> bit_offs) & this_byte) >> (8 - bit_offs - num_of_bits);
        decom_state->curr_bits_offset += num_of_bits;
    }
    else {
        next_byte_bits = (num_of_bits + bit_offs) % 8;
        next_byte = buffer[decom_state->curr_byte + 1];
        *res = (((initial >> bit_offs) & this_byte) << next_byte_bits) | (next_byte >> (8 - next_byte_bits));
        decom_state->curr_byte++;
        decom_state->curr_bits_offset = (bit_offs + num_of_bits) % 8;
    }
    return 0;
}

int append_comp_byte_block(struct bcomp_state_block *comp_state_block, uint8_t byte, uint8_t high_bits) {
    if(comp_state_block == NULL) {
        return -1;
    }
    comp_state_block->total_bits += high_bits;
    if(comp_state_block->curr_bits_suffix == 0) {
        comp_state_block->curr_byte++;
        comp_state_block->bytes_block[comp_state_block->curr_byte] = byte;
        comp_state_block->curr_bits_suffix = 8 - high_bits;
        return 0;
    }

    if(comp_state_block->curr_bits_suffix >= high_bits) {
        comp_state_block->bytes_block[comp_state_block->curr_byte] |= (byte >> (8 - comp_state_block->curr_bits_suffix));
        comp_state_block->curr_bits_suffix -= high_bits;
    }
    else {
        comp_state_block->bytes_block[comp_state_block->curr_byte] |= (byte >> (8 - comp_state_block->curr_bits_suffix));
        comp_state_block->curr_byte++;
        comp_state_block->bytes_block[comp_state_block->curr_byte] |= (byte << comp_state_block->curr_bits_suffix);
        comp_state_block->curr_bits_suffix += (8 - high_bits);
    }
    return 0;
}

int init_freq_table(struct freq_matrix freq_table[], const uint16_t num_elems) {
    if(freq_table == NULL) {
        return -1;
    }
    if(num_elems > FREQUENCY_TABLE_SIZE || num_elems < 1) {
        return -3;
    }
    for(uint16_t i = 0; i < num_elems; i++) {
        freq_table[i].index = i;
        freq_table[i].freq = 0;
    }
    return 0;
}

int create_dict_table(const struct freq_matrix sorted_freq_table[], uint8_t dict_elem_table[], uint8_t num_dict_elems) {
    if(sorted_freq_table == NULL || dict_elem_table == NULL) {
        return -1;
    }
    for(uint8_t i = 0; i < num_dict_elems; i++) {
        dict_elem_table[i] = sorted_freq_table[i].index;
    }
    return 0;
}

int sort_and_parse_freq(const struct freq_matrix freq_table[], const uint16_t freq_elems, const uint16_t num_raw_bytes, const uint8_t num_raw_states, struct block_comp_option *block_comp_opt) {
    if(freq_table == NULL || block_comp_opt == NULL) {
        return -1;
    }
    if(freq_elems > FREQUENCY_TABLE_SIZE || freq_elems < 1) {
        return -3;
    }
    if(num_raw_bytes < 1 || num_raw_states < 1) {
        return -5;
    }
    struct freq_matrix freq_table_copy[FREQUENCY_TABLE_SIZE];
    init_freq_table(freq_table_copy, FREQUENCY_TABLE_SIZE);
    memcpy(freq_table_copy, freq_table, freq_elems * sizeof(struct freq_matrix));
    qsort(freq_table_copy, FREQUENCY_TABLE_SIZE, sizeof(struct freq_matrix), compare);

    const uint8_t num_dict_elems[6] = {2, 4, 8, 16, 32, 64};
    const uint8_t dict_elem_size[6][3] = {
        {1, 4, 8},
        {2, 4, 8},
        {3, 6, 8},
        {4, 6, 8},
        {5, 7, 8},
        {6, 7, 8},
    };
    const uint16_t dict_total_size[6][3] = {
        {2,   8,   16},
        {8,   16,  32},
        {24,  48,  64},
        {64,  96,  128},
        {160, 224, 256},
        {384, 448, 512}
    };
    const uint8_t comp_byte_size[6] = {1, 2, 3, 4, 5, 6};

    float raw_bits = (float)num_raw_bytes * 8;
    
    uint32_t top_freqs[6] = {0x00, };
    uint8_t top_idx_max_tmp = 0, top_idx_max[6] = {0x00, };
    float comp_ratios[6] = {0.0, };

    if(freq_table_copy[0].freq == num_raw_bytes) {
        block_comp_opt->block_comp_flag = 1;
        block_comp_opt->block_comp_method = 0;
        block_comp_opt->dict_elem_code = 3;
        block_comp_opt->num_raw_states = num_raw_states;
        block_comp_opt->num_raw_bytes = num_raw_bytes;
        block_comp_opt->dict_elem_bits = 8;
        block_comp_opt->num_dict_elems = 1;
        block_comp_opt->comp_byte_size = 0;
        memset(block_comp_opt->dict_elem_table, 0, 64 * sizeof(uint8_t));
        create_dict_table(freq_table_copy, block_comp_opt->dict_elem_table, 1);
        block_comp_opt->comp_ratio = 17.0 / raw_bits;
        return 0;
    }

    uint16_t i = 0, j = 0, jmin = 0, jmax = 0;
    uint8_t top_freqs_adj[6][3] = {
        {0,},
    };
    uint8_t min_tmp = 0, max_tmp = 0;
    for(i = 0; i < 6; i++) {
        if(i == 0) {
            top_freqs[i] = 0;
            jmin = 0;
            top_idx_max_tmp = 0;
        }
        else {
            top_freqs[i] = top_freqs[i - 1];
            top_idx_max_tmp = top_idx_max[i - 1];
            jmin = 0x01 << i;
        }
        jmax = 0x01 << (i + 1);
        for(j = jmin; j < jmax; j++) {
            top_freqs[i] += freq_table_copy[j].freq;
            if(freq_table_copy[j].index > top_idx_max_tmp) {
                top_idx_max_tmp = freq_table_copy[j].index;
            }
        }
        top_idx_max[i] = top_idx_max_tmp;
        min_tmp = freq_table_copy[j].index;
        max_tmp = freq_table_copy[j].index;
        for(j = jmax; j < 256 && freq_table_copy[j].freq != 0; j++) {
            if(freq_table_copy[j].index < min_tmp) {
                min_tmp = freq_table_copy[j].index;
            }
            if(freq_table_copy[j].index > max_tmp) {
                max_tmp = freq_table_copy[j].index;
            }
        }
        top_freqs_adj[i][0] = min_tmp;

        if(min_tmp < 16) {
            top_freqs_adj[i][1] = 0;
        }
        else {
            top_freqs_adj[i][1] = 1;
        }

        if(max_tmp - min_tmp < 2) {
            top_freqs_adj[i][2] = 1;
        }
        else if(max_tmp - min_tmp < 4) {
            top_freqs_adj[i][2] = 2;
        }
        else if(max_tmp - min_tmp < 8) {
            top_freqs_adj[i][2] = 3;
        }
        else if(max_tmp - min_tmp < 16) {
            top_freqs_adj[i][2] = 4;
        }
        else if(max_tmp - min_tmp < 32) {
            top_freqs_adj[i][2] = 5;
        }
        else if(max_tmp - min_tmp < 64) {
            top_freqs_adj[i][2] = 6;
        }
        else if(max_tmp - min_tmp < 128) {
            top_freqs_adj[i][2] = 7;
        }
        else {
            top_freqs_adj[i][2] = 8;
        }
    }

    if(top_idx_max[0] < 2) {
        top_idx_max[0] = 0;
    }
    else if(top_idx_max[0] < 16) {
        top_idx_max[0] = 1;
    }
    else {
        top_idx_max[0] = 2;
    }

    if(top_idx_max[1] < 4) {
        top_idx_max[1] = 0;
    }
    else if(top_idx_max[1] < 16) {
        top_idx_max[1] = 1;
    }
    else {
        top_idx_max[1] = 2;
    }

    if(top_idx_max[2] < 8) {
        top_idx_max[2] = 0;
    }
    else if(top_idx_max[2] < 64) {
        top_idx_max[2] = 1;
    }
    else {
        top_idx_max[2] = 2;
    }

    if(top_idx_max[3] < 16) {
        top_idx_max[3] = 0;
    }
    else if(top_idx_max[3] < 64) {
        top_idx_max[3] = 1;
    }
    else {
        top_idx_max[3] = 2;
    }

    if(top_idx_max[4] < 32) {
        top_idx_max[4] = 0;
    }
    else if(top_idx_max[4] < 128) {
        top_idx_max[4] = 1;
    }
    else {
        top_idx_max[4] = 2;
    }

    if(top_idx_max[5] < 64) {
        top_idx_max[5] = 0;
    }
    else if(top_idx_max[5] < 128) {
        top_idx_max[5] = 1;
    }
    else {
        top_idx_max[5] = 2;
    }
    
    for(i = 0; i < 6; i++) {
        uint8_t incomp_min_size = (top_freqs_adj[i][1] == 1) ? 8 : 4;
        comp_ratios[i] = (float)(10 + incomp_min_size + 3 + dict_total_size[i][top_idx_max[i]] + top_freqs[i] * comp_byte_size[i] + (num_raw_bytes - top_freqs[i]) * (1 + top_freqs_adj[i][2])) / raw_bits;
    }

    float comp_ratio_tmp = comp_ratios[0];
    uint8_t comp_method_tmp = 0;

    for(i = 1; i < 6; i++) {
        if(comp_ratios[i] < comp_ratio_tmp) {
            comp_ratio_tmp = comp_ratios[i];
            comp_method_tmp = i;
        }
    }

    uint8_t min_g = freq_table_copy[0].index, max_g = freq_table_copy[0].index;
    uint16_t uniq_g = 0;
    for(uint16_t k = 1; k < 256 && freq_table_copy[k].freq != 0; k++) {
        uniq_g++;
        if(freq_table_copy[k].index < min_g) {
            min_g = freq_table_copy[k].index;
        }
        if(freq_table_copy[k].index > max_g) {
            max_g = freq_table_copy[k].index;
        }
    }
    uint8_t incomp_size_g = 0;
    float incomp_ratio_g = 0.0;
    uint8_t min_size_g = 0;
    if(max_g - min_g < 2) {
        incomp_size_g = 1;
    }   
    else if(max_g - min_g < 4) {
        incomp_size_g = 2;
    }
    else if(max_g - min_g < 8) {
        incomp_size_g = 3;
    }
    else if(max_g - min_g < 16) {
        incomp_size_g = 4;
    }
    else if(max_g - min_g < 32) {
        incomp_size_g = 5;
    }
    else if(max_g - min_g < 64) {
        incomp_size_g = 6;
    }
    else if(max_g - min_g < 128) {
        incomp_size_g = 7;
    }
    else {
        incomp_size_g = 0;
    }

    if(min_g < 16) {
        min_size_g = 0;
    }
    else {
        min_size_g = 1;
    }

    incomp_ratio_g = (5 + ((min_size_g == 0) ? 4 : 8) + 3 + num_raw_bytes * ((incomp_size_g == 0) ? 8 : incomp_size_g)) / raw_bits;
    if(comp_ratio_tmp > incomp_ratio_g) {
        if(incomp_ratio_g < block_comp_opt->comp_ratio) {
            block_comp_opt->block_comp_flag = 0;
            block_comp_opt->block_incomp_size = incomp_size_g;
            block_comp_opt->block_incomp_min = min_g;
            block_comp_opt->block_incomp_min_size = min_size_g;
            block_comp_opt->num_raw_states = num_raw_states;
            block_comp_opt->num_raw_bytes = num_raw_bytes;
            block_comp_opt->comp_ratio = incomp_ratio_g;
        }
        return 0;
    }
    else {
        if(comp_ratio_tmp < block_comp_opt->comp_ratio) {
            block_comp_opt->block_comp_flag = 1;
            block_comp_opt->block_comp_method = comp_method_tmp;
            block_comp_opt->dict_elem_code = top_idx_max[comp_method_tmp];
            block_comp_opt->num_raw_states = num_raw_states;
            block_comp_opt->num_raw_bytes = num_raw_bytes;
            block_comp_opt->dict_elem_bits = dict_elem_size[comp_method_tmp][top_idx_max[comp_method_tmp]];
            block_comp_opt->num_dict_elems = num_dict_elems[comp_method_tmp];
            block_comp_opt->comp_byte_size = comp_byte_size[comp_method_tmp];
            memset(block_comp_opt->dict_elem_table, 0, 64 * sizeof(uint8_t));
            create_dict_table(freq_table_copy, block_comp_opt->dict_elem_table, num_dict_elems[comp_method_tmp]);
            block_comp_opt->comp_incomp_min = top_freqs_adj[comp_method_tmp][0];
            block_comp_opt->comp_incomp_flag = top_freqs_adj[comp_method_tmp][1];
            block_comp_opt->comp_incomp_bits = top_freqs_adj[comp_method_tmp][2];
            block_comp_opt->comp_ratio = comp_ratio_tmp;
        }
        return 0;
    }
}

int8_t block_compress_core(const uint8_t block[], const uint16_t block_raw_bytes, struct bcomp_state_block *comp_state_block, uint16_t *prev_bytes, uint16_t *rest_bytes) {
    if(block == NULL || comp_state_block == NULL || prev_bytes == NULL || rest_bytes == NULL) {
        return -1;
    }
    if(block_raw_bytes > FULL_BLOCK_BYTES) {
        return -3;
    }
    memset(comp_state_block->bytes_block, 0, (FULL_BLOCK_BYTES + 1) * sizeof(uint8_t));

    comp_state_block->curr_bits_suffix = 8;
    comp_state_block->curr_byte = 0;
    comp_state_block->total_bits = 0;
    comp_state_block->io_end = 0;

    if(block_raw_bytes == 0) {
        comp_state_block->io_end = 1;
        *prev_bytes = 0;
        *rest_bytes = 0;
        return 0;
    }

    uint8_t total_states = (block_raw_bytes % FULL_STATE_BYTES) ? (block_raw_bytes / FULL_STATE_BYTES + 1) : (block_raw_bytes / FULL_STATE_BYTES);
    uint8_t block_io_end = (total_states < BLOCK_MAX_STATE_NUM) | ((total_states == BLOCK_MAX_STATE_NUM) && (block_raw_bytes % FULL_STATE_BYTES));
    uint16_t last_state_bytes = (block_raw_bytes % FULL_STATE_BYTES) ? (block_raw_bytes % FULL_STATE_BYTES) : (FULL_STATE_BYTES);

    /* Initialize the block compression option. */
    struct block_comp_option block_comp_opt;
    memset(&block_comp_opt, 0, sizeof(struct block_comp_option));
    block_comp_opt.block_comp_method = 0xFF;
    block_comp_opt.comp_byte_size = 0xFF;
    block_comp_opt.comp_ratio = 2.0;
    block_comp_opt.dict_elem_bits = 0xFF;
    block_comp_opt.dict_elem_code = 0xFF;
    block_comp_opt.num_dict_elems = 0xFF;
    block_comp_opt.num_raw_bytes = block_raw_bytes;
    block_comp_opt.num_raw_states = total_states;

    struct freq_matrix freq_table[FREQUENCY_TABLE_SIZE];
    init_freq_table(freq_table, FREQUENCY_TABLE_SIZE);
    uint16_t num_raw_bytes = 0;
    uint16_t num_raw_states = 0;
    uint16_t curr_state_bytes = 0;

    uint16_t i = 0, j = 0;
    int8_t freq_pos = 0;

    for(i = 0; i < total_states; i++) {
        num_raw_states = i + 1;
        curr_state_bytes = (i == (total_states - 1)) ? last_state_bytes : FULL_STATE_BYTES;
        num_raw_bytes = i * FULL_STATE_BYTES + curr_state_bytes;
        for(j = 0; j < curr_state_bytes; j++) {
            freq_table[block[i*FULL_STATE_BYTES + j]].freq++;
        }
        sort_and_parse_freq(freq_table, FREQUENCY_TABLE_SIZE, num_raw_bytes, num_raw_states, &block_comp_opt);
    }

    uint8_t real_io_end = (block_io_end) && (block_comp_opt.num_raw_bytes == block_raw_bytes);
    comp_state_block->io_end = real_io_end;
    /* If the whole block is uncompressible, just add a header 0 */
    if(block_comp_opt.block_comp_flag == 0) {
        append_comp_byte_block(comp_state_block, 0x00, 1);
        append_comp_byte_block(comp_state_block, block_comp_opt.block_incomp_size << 5, 3);
        append_comp_byte_block(comp_state_block, block_comp_opt.block_incomp_min_size << 7, 1);
        uint8_t min_size = 4 * (block_comp_opt.block_incomp_min_size + 1);
        append_comp_byte_block(comp_state_block, block_comp_opt.block_incomp_min << (8 - min_size), min_size);
        append_comp_byte_block(comp_state_block, block_comp_opt.num_raw_states << 5, 3);
        
        uint8_t low_bits = (block_comp_opt.block_incomp_size == 0) ? 8 : block_comp_opt.block_incomp_size;
        for(i = 0; i < block_comp_opt.num_raw_bytes; i++) {
            append_comp_byte_block(comp_state_block, (block[i] - block_comp_opt.block_incomp_min) << (8 - low_bits), low_bits);
        }
        *prev_bytes = block_comp_opt.num_raw_bytes;
        *rest_bytes = block_raw_bytes - *prev_bytes;
        return 0; 
    }

    /* Padding the header of 1 */
    append_comp_byte_block(comp_state_block, 0x80, 1);
    append_comp_byte_block(comp_state_block, block_comp_opt.block_comp_method << 5, 3);
    append_comp_byte_block(comp_state_block, block_comp_opt.dict_elem_code << 6, 2);
    append_comp_byte_block(comp_state_block, block_comp_opt.num_raw_states << 5, 3);

    if(block_comp_opt.block_comp_method == 0 && block_comp_opt.dict_elem_code == 3) {
        append_comp_byte_block(comp_state_block, block_comp_opt.dict_elem_table[0], 8);
        if(real_io_end) {
            append_comp_byte_block(comp_state_block, (uint8_t)last_state_bytes, 8);
        }
        *prev_bytes = block_comp_opt.num_raw_bytes;
        *rest_bytes = block_raw_bytes - *prev_bytes;
        return 0;
    }

    append_comp_byte_block(comp_state_block, block_comp_opt.comp_incomp_flag << 7, 1);
    uint8_t incomp_min_bits = ((block_comp_opt.comp_incomp_flag == 0) ? 4 : 8);
    append_comp_byte_block(comp_state_block, block_comp_opt.comp_incomp_min << (8 - incomp_min_bits), incomp_min_bits);
    append_comp_byte_block(comp_state_block, block_comp_opt.comp_incomp_bits << 5, 3);

    for(i = 0; i < block_comp_opt.num_dict_elems; i++) {
        append_comp_byte_block(comp_state_block, block_comp_opt.dict_elem_table[i] << (8 - block_comp_opt.dict_elem_bits), block_comp_opt.dict_elem_bits);
    }

    for(i = 0; i < block_comp_opt.num_raw_bytes; i++) {
        freq_pos = is_in_dict(block_comp_opt.dict_elem_table, 0, block_comp_opt.num_dict_elems, block_comp_opt.num_dict_elems, block[i]);
        if(freq_pos == -3) {
            return -5;
        }
        /* Uncompressible byte found. */
        if(freq_pos < 0) {
            append_comp_byte_block(comp_state_block, (uint8_t)0x00, 1);
            append_comp_byte_block(comp_state_block, (block[i] - block_comp_opt.comp_incomp_min) << (8 - block_comp_opt.comp_incomp_bits), block_comp_opt.comp_incomp_bits);
            continue;
        }
        append_comp_byte_block(comp_state_block, (uint8_t)0x80, 1);
        append_comp_byte_block(comp_state_block, (freq_pos << (8 - block_comp_opt.comp_byte_size)), block_comp_opt.comp_byte_size);
    }
    *prev_bytes = block_comp_opt.num_raw_bytes;
    *rest_bytes = block_raw_bytes - *prev_bytes;
    return 0; 
}

int check_header_validity(const uint8_t comp_method, const uint8_t dict_elem_code) {
    if(comp_method >= COMP_METHOD_MAX) {
        return INVALID_HEADER_FLAG;
    }
    if(comp_method == 0) {
        if(dict_elem_code >= DICT_ELEM_CODE_MAX_A) {
            return INVALID_HEADER_FLAG;
        }
    }
    else {
        if(dict_elem_code >= DICT_ELEM_CODE_MAX_BCD) {
            return INVALID_HEADER_FLAG;
        }
    }
    return 0;
}

int file_decomp_core(FILE *stream, FILE *target, const uint64_t buffer_size_byte, const int64_t file_size, const uint8_t tail_byte){
    if(stream == NULL || target == NULL || file_size < 1) {
        return -1;
    }

    uint16_t i = 0;
    uint8_t comp_flag = 0;
    uint8_t state_buffer[FULL_BLOCK_BYTES] = {0x00, };
    
    struct decomp_state decom_state;
    memset(&decom_state, 0, sizeof(struct decomp_state));

    const uint8_t num_dict_elems[6] = {2, 4, 8, 16, 32, 64};
    const uint8_t dict_elem_size[6][3] = {
        {1, 4, 8},
        {2, 4, 8},
        {3, 6, 8},
        {4, 6, 8},
        {5, 7, 8},
        {6, 7, 8},
    };

    const uint8_t comp_byte_size[6] = {1, 2, 3, 4, 5, 6};
    uint8_t dict_elems[64] = {0x00,};
    
    uint8_t dict_elem_index = 0;
    uint8_t byte_comp_flag = 0;
    uint8_t comp_method = 0, dict_elem_code = 0;
    uint64_t start_pos = 0;
    uint8_t comp_states = 0;
    uint8_t incomp_size = 0;
    uint8_t incomp_min = 0;
    uint8_t incomp_byte = 0;
    uint8_t incomp_min_size = 0;
    uint8_t incomp_states = 0;

    uint8_t *buffer = (uint8_t *)calloc(buffer_size_byte, sizeof(uint8_t));
    if(buffer == NULL) {
        return -3;
    }
    while(1) {
        if(decomp_read_end(file_size, tail_byte, decom_state)) {
            free(buffer);
            return 0;
        }
        memset(state_buffer, 0, FULL_BLOCK_BYTES);
        get_next_bits(buffer, buffer_size_byte, 1, &comp_flag, &decom_state, stream);
        if(comp_flag == 0) {
            get_next_bits(buffer, buffer_size_byte, 3, &incomp_size, &decom_state, stream);
            get_next_bits(buffer, buffer_size_byte, 1, &incomp_min_size, &decom_state, stream);
            incomp_min_size = (incomp_min_size == 0) ? 4 : 8;
            get_next_bits(buffer, buffer_size_byte, incomp_min_size, &incomp_min, &decom_state, stream);
            incomp_size = (incomp_size == 0) ? 8 : incomp_size;
            get_next_bits(buffer, buffer_size_byte, 3, &incomp_states, &decom_state, stream);
            incomp_states = (incomp_states == 0) ? 8 : incomp_states;
            for(i = 0; i < (incomp_states * FULL_STATE_BYTES) && (!decomp_read_end(file_size, tail_byte, decom_state)); i++) {
                get_next_bits(buffer, buffer_size_byte, incomp_size, &incomp_byte, &decom_state, stream);
                state_buffer[i] = incomp_min + incomp_byte;
            }
            fwrite(state_buffer, sizeof(uint8_t), i - start_pos, target);
            if(decomp_read_end(file_size, tail_byte, decom_state)) {
                free(buffer);
                return 0;
            }
            continue;
        }

        get_next_bits(buffer, buffer_size_byte, 3, &comp_method, &decom_state, stream);
        get_next_bits(buffer, buffer_size_byte, 2, &dict_elem_code, &decom_state, stream);
        if(check_header_validity(comp_method, dict_elem_code) == INVALID_HEADER_FLAG) {
            free(buffer);
            return INVALID_HEADER_FLAG;
        }
        get_next_bits(buffer, buffer_size_byte, 3, &comp_states, &decom_state, stream);
        comp_states = (comp_states == 0) ? 8 : comp_states;

        if(comp_method == 0 && dict_elem_code == 3) {
            uint8_t unique_dict_elem = 0;
            uint8_t unique_elem_last = 0;
            uint16_t unique_elem_last_real = 0;
            uint16_t unique_elem_total = 0;
            get_next_bits(buffer, buffer_size_byte, 8, &unique_dict_elem, &decom_state, stream);
            if(tail_byte == 0x00) {
                if((decom_state.stream_bytes_curr + decom_state.curr_byte == file_size - 2) && (decom_state.curr_bits_offset == 0)) {
                    get_next_bits(buffer, buffer_size_byte, 8, &unique_elem_last, &decom_state, stream);
                }
            }
            else {
                if((decom_state.stream_bytes_curr + decom_state.curr_byte == file_size - 3) && (decom_state.curr_bits_offset == tail_byte)) {
                    get_next_bits(buffer, buffer_size_byte, 8, &unique_elem_last, &decom_state, stream);
                }
            }
            unique_elem_last_real = (unique_elem_last == 0x00) ? FULL_STATE_BYTES : unique_elem_last;
            unique_elem_total = FULL_STATE_BYTES * (comp_states - 1) + unique_elem_last_real;
            for(i = 0; i < unique_elem_total; i++) {
                state_buffer[i] = unique_dict_elem;
            }
            fwrite(state_buffer, sizeof(uint8_t), unique_elem_total, target);
            if(decomp_read_end(file_size, tail_byte, decom_state)) {
                free(buffer);
                return 0;
            }
            continue;
        }

        uint8_t incomp_min_bits = 0, incomp_min = 0, incomp_bits = 0, incomp_byte = 0;
        get_next_bits(buffer, buffer_size_byte, 1, &incomp_min_bits, &decom_state, stream);
        incomp_min_bits = (incomp_min_bits == 0) ? 4 : 8;
        get_next_bits(buffer, buffer_size_byte, incomp_min_bits, &incomp_min, &decom_state, stream);
        get_next_bits(buffer, buffer_size_byte, 3, &incomp_bits, &decom_state, stream);
        incomp_bits = (incomp_bits == 0) ? 8 : incomp_bits;
        for(i = 0; i < num_dict_elems[comp_method]; i++) {
            get_next_bits(buffer, buffer_size_byte, dict_elem_size[comp_method][dict_elem_code], dict_elems + i, &decom_state, stream);
        }

        for(i = 0; i < comp_states * FULL_STATE_BYTES && (!decomp_read_end(file_size, tail_byte, decom_state)); i++) {
            get_next_bits(buffer, buffer_size_byte, 1, &byte_comp_flag, &decom_state, stream);
            if(byte_comp_flag == 0) {
                get_next_bits(buffer, buffer_size_byte, incomp_bits, &incomp_byte, &decom_state, stream);
                state_buffer[i] = incomp_min + incomp_byte;
                continue;
            }
            get_next_bits(buffer, buffer_size_byte, comp_byte_size[comp_method], &dict_elem_index, &decom_state, stream);
            if(dict_elem_index >= num_dict_elems[comp_method]) {
                free(buffer);
                return INVALID_DATA_TO_DECOMP;
            }
            state_buffer[i] = dict_elems[dict_elem_index];
        }
        fwrite(state_buffer, sizeof(uint8_t), i - start_pos, target);
        if(decomp_read_end(file_size, tail_byte, decom_state)) {
            free(buffer);
            return 0;
        }
    }
}

int padding_comp_obuffer(const struct bcomp_state_block *comp_state_block, struct bcomp_obuffer_block *output_buffer) {
    if(comp_state_block == NULL || output_buffer == NULL) {
        return -1;
    }
    memset(output_buffer->bytes_array_block, 0, (FULL_BLOCK_BYTES + 1) * sizeof(uint8_t));
    output_buffer->io_end = comp_state_block->io_end;
    output_buffer->bytes_valid = 0;
    //uint8_t initial = 0xFF;
    uint16_t i = 0;

    uint8_t tail_byte_prev = output_buffer->prev_tail; 
    uint8_t tail_bits_prev = output_buffer->prev_tail_high_bits;
    uint16_t total_bits = tail_bits_prev + comp_state_block->total_bits;
    uint8_t tail_bits_new = total_bits % 8;
    uint16_t total_bytes = total_bits / 8;

    output_buffer->bytes_array_block[0] = tail_byte_prev | (comp_state_block->bytes_block[0] >> tail_bits_prev);
    i++;

    while(i < total_bytes) {
        output_buffer->bytes_array_block[i] = (comp_state_block->bytes_block[i-1] << (8 - tail_bits_prev)) | (comp_state_block->bytes_block[i] >> tail_bits_prev);
        i++;
    }

    output_buffer->prev_tail_high_bits = tail_bits_new;
    output_buffer->bytes_valid = total_bytes;
    if(output_buffer->io_end == 0) {
        output_buffer->prev_tail = (comp_state_block->bytes_block[i-1] << (8 - tail_bits_prev)) | (comp_state_block->bytes_block[i] >> tail_bits_prev);
    }
    else {
        output_buffer->bytes_array_block[i] = (comp_state_block->bytes_block[i-1] << (8 - tail_bits_prev)) | (comp_state_block->bytes_block[i] >> tail_bits_prev);
        if(tail_bits_new != 0) {
            output_buffer->bytes_valid++;
        }
    }
    return 0;
}

int fwrite_comp(FILE *file_p, const struct bcomp_obuffer_block *output_buffer) {
    if(file_p == NULL) {
        return -1;
    }
    if(fwrite(output_buffer->bytes_array_block, sizeof(uint8_t), output_buffer->bytes_valid, file_p) != output_buffer->bytes_valid) {
        return -3;
    }
    if(output_buffer->io_end) {
        fwrite(&(output_buffer->prev_tail_high_bits), sizeof(uint8_t), 1, file_p);
        return 1;
    }
    return 0;
}

int file_bcomp(const char *source, const char *target) {
#ifdef _WIN32
    FILE *filep_s = NULL;
    FILE *filep_t = NULL;
    errno_t file_io_flag = fopen_s(&filep_s, source, "rb");
    if(filep_s == NULL) {
        return FILE_IO_ERROR;
    }
    file_io_flag = fopen_s(&filep_t, target, "wb+");
    if(filep_t == NULL) {
        fclose(filep_s);
        return FILE_IO_ERROR;
    }
#else 
    FILE *filep_s = fopen(source, "rb");
    if(filep_s == NULL) {
        return FILE_IO_ERROR;
    }
    FILE *filep_t = fopen(target, "wb+");
    if(filep_t == NULL) {
        fclose(filep_s);
        return FILE_IO_ERROR;
    }
#endif
    uint8_t ingest_buffer_comp[FULL_BLOCK_BYTES] = {0x00, };
    uint8_t ingest_buffer_prev[FULL_BLOCK_BYTES] = {0x00, };
    struct bcomp_state_block comp_state;
    struct bcomp_obuffer_block output_buffer;
    int8_t err_flag = 0, fwrite_flag = 0;
    memset(&comp_state, 0, sizeof(struct bcomp_state_block));
    memset(&output_buffer, 0, sizeof(struct bcomp_obuffer_block));
    size_t bytes_read = 0;
    uint16_t prev_bytes, new_bytes_max = 0, rest_bytes = 0;
    while(1) {
        /* Read a full block from the file stream. */
        new_bytes_max = FULL_BLOCK_BYTES - rest_bytes;
        memcpy(ingest_buffer_comp, ingest_buffer_prev + prev_bytes, rest_bytes * sizeof(uint8_t));
        bytes_read = fread(ingest_buffer_comp + rest_bytes, sizeof(uint8_t), new_bytes_max, filep_s);
        if(block_compress_core(ingest_buffer_comp, GET_MIN(bytes_read, new_bytes_max) + rest_bytes, &comp_state, &prev_bytes, &rest_bytes) < 0) {
            err_flag = -1;
            goto close_and_return;
        }
        
        if(padding_comp_obuffer(&comp_state, &output_buffer) != 0) {
            err_flag = -3;
            goto close_and_return;
        }
        fwrite_flag = fwrite_comp(filep_t, &output_buffer);
        if(fwrite_flag < 0) {
            err_flag = -5;
            goto close_and_return;
        }
        else if(fwrite_flag == 1) {
            goto close_and_return;
        }
        memcpy(ingest_buffer_prev, ingest_buffer_comp, FULL_BLOCK_BYTES * sizeof(uint8_t));
    }
close_and_return:
    fclose(filep_s);
    fclose(filep_t);
    return err_flag;
}


int file_bcomp_decomp(const char *source, const char *target) {
#ifdef _WIN32
    FILE *filep_s = NULL;
    errno_t file_io_flag = fopen_s(&filep_s, source, "rb");
    if(filep_s == NULL) {
        return FILE_IO_ERROR;
    }
#else
    FILE* filep_s = fopen(source, "rb");
    if(filep_s == NULL) {
        return FILE_IO_ERROR;
    }
#endif
    uint64_t read_buffer_size = 0;
    uint8_t tail_byte = 0x00;
#ifdef _WIN32
    _fseeki64(filep_s, -1, SEEK_END);
    int64_t file_size = _ftelli64(filep_s) + 1;
#else
    fseeko(filep_s, -1, SEEK_END);
    int64_t file_size = ftello(filep_s) + 1;
#endif
    if(fread(&tail_byte, sizeof(uint8_t), 1, filep_s) != 1 || tail_byte > 7) {
        fclose(filep_s);
        return INVALID_FILE_TO_DECOMP;
    }
    rewind(filep_s);
    if(file_size > 0x10000) {
        read_buffer_size = 65536;
    }
    else {
        read_buffer_size = 2048;
    }
#ifdef _WIN32
    FILE *filep_t = NULL;
    file_io_flag = fopen_s(&filep_t, target, "wb+");
    if(filep_t == NULL) {
        fclose(filep_s);
        return FILE_IO_ERROR;
    }
#else
    FILE *filep_t = fopen(target, "wb+");
    if(filep_t == NULL) {
        fclose(filep_s);
        return FILE_IO_ERROR;
    }
#endif
    int err_flag = file_decomp_core(filep_s, filep_t, read_buffer_size, file_size, tail_byte);
    fclose(filep_s);
    fclose(filep_t);
    if(err_flag == INVALID_HEADER_FLAG) {
        return INVALID_HEADER_FLAG;
    }
    else if(err_flag == INVALID_DATA_TO_DECOMP) {
        return INVALID_DATA_TO_DECOMP;
    }
    else if(err_flag != 0 && err_flag != 1) {
        return -err_flag;
    }
    else {
        return 0;
    }
}
#if defined fuzz && fuzz == 1

#include <stdio.h>
#include <string.h>

#define test(x) do{ if(!(x)){ int volatile* volatile ptr; ptr = 0; *ptr = 0; } }while(0)

void fuzz_1(uint8_t const* const data, size_t const size)
{
	FILE* f;
	size_t len;
	int err;
	uint8_t buff[8 * 1024];

	f = fopen("data_a.dat", "wb"); test(f);
	len = fwrite(data, 1, size, f); test(len == size);
	err = fclose(f); test(err == 0);
	err = file_bcomp("data_a.dat", "data_b.dat"); test(err == 0);
	err = file_bcomp_decomp("data_b.dat", "data_c.dat"); test(err == 0);
	f = fopen("data_c.dat", "rb"); test(f);
	len = fread(&buff[0], 1, 8 * 1024, f);
	err = fclose(f); test(err == 0);
	test(len == size);
	test(memcmp(&buff[0], data, size) == 0);
}

void fuzz_2(uint8_t const* const data, size_t const size)
{
	FILE* f;
	size_t len;
	int err;

	f = fopen("data_d.dat", "wb"); test(f);
	len = fwrite(data, 1, size, f); test(len == size);
	err = fclose(f); test(err == 0);
	err = file_bcomp_decomp("data_d.dat", "data_e.dat"); ((void)(err));
}

int LLVMFuzzerTestOneInput(uint8_t const* const data, size_t const size)
{
	fuzz_1(data, size);
	fuzz_2(data, size);
	return 0;
}

#else

void print_help(void) {
    printf("Error:   Please specify option, source and target path.\n");
    printf("Usage:   bcomp OPTION SOURCE_FILE TARGET_FILE.\n");
    printf("         OPTION:    -c    Compress the source file to target file.\n");
    printf("                    -d    Decompress the source file to target file.\n");
    printf("Example: ./bcomp -c foo.txt bar.bcmp\n");
    printf("Repository: https://github.com/zhenrong-wang/bcomp \n");
}

int main(int argc, char **argv) {
    if(argc < 4) {
        print_help();
        return 1;
    }
    if(strcmp(argv[1], "-c") != 0 && strcmp(argv[1], "-d") != 0) {
        print_help();
        return 3;
    }
    int run_flag = 0;
    char comp_filename[2048] = "";
    char decomp_filename[2048] = "";
    snprintf(comp_filename, 2048, "%s.bc", argv[3]);
    snprintf(decomp_filename, 2048, "%s.dc", argv[3]);
    if(strcmp(argv[1], "-c") == 0) {
        run_flag = file_bcomp(argv[2], comp_filename);
        printf("INFO: Compressed file %s to %s . Return Value: %d.\n", argv[2], comp_filename, run_flag);
    }
    else {
        run_flag = file_bcomp_decomp(argv[2], decomp_filename);
        if(run_flag != 0) {
            printf("ERRO: Decompression failed. Error Code: %d.\n", run_flag);
        }
        else {
            printf("INFO: Decompressed file %s to %s .\n", argv[2], decomp_filename);
        }
    }
    printf("Repository: https://github.com/zhenrong-wang/bcomp \n");
    return 0;
}
#endif
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

#define FULL_STATE_BYTES        256
#define DECOMP_INGEST_BYTES     1024
#define COMP_METHOD_MAX         3
#define DICT_ELEM_CODE_MAX_A    3  
#define DICT_ELEM_CODE_MAX_BCD  2
#define COMP_FILE_MIN_SIZE      4
#define INVALID_HEADER_FLAG     127
#define INVALID_TAIL_INFO       125
#define INVALID_FILE_TO_DECOMP  123
#define FILE_IO_ERROR           121
#define INVALID_DATA_TO_DECOMP  119

struct freq_matrix {
    uint8_t index;
    uint16_t freq;
};

struct bcomp_byte {
    uint8_t byte_high_value;
    uint8_t suffix_bits;
};

struct bcomp_obuffer {
    uint8_t bytes_array[257];
    uint16_t bytes_valid;
    uint8_t prev_tail;
    uint8_t prev_tail_high_bits;
    uint8_t io_end;
};

struct bcomp_state {
    uint8_t  bytes[257];
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

int compare(const void *a, const void *b) {  
    struct freq_matrix *ptr_a = (struct freq_matrix *)a;
    struct freq_matrix *ptr_b = (struct freq_matrix *)b;
    return ptr_b->freq - ptr_a->freq;
}

int8_t is_top_freq(const struct freq_matrix *frequency, const uint8_t start, const uint8_t end, const uint8_t byte) {
    for(uint8_t i = start; i < end; i++) {
        if(byte == frequency[i].index) {
            return i;
        }
    }
    return -1;
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
            return -11;
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

int append_comp_byte(struct bcomp_state *comp_state, uint8_t byte, uint8_t high_bits) {
    if(comp_state == NULL) {
        return -1;
    }
    comp_state->total_bits += high_bits;
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
int8_t compress_core(const uint8_t state[], const uint16_t raw_bytes, struct bcomp_state *comp_state) {
    if(state == NULL || comp_state == NULL) {
        return -1;
    }
    if(raw_bytes > FULL_STATE_BYTES) {
        return -3;
    }
    
    memset(comp_state->bytes, 0, 257 * sizeof(uint8_t));
    comp_state->curr_bits_suffix = 8;
    comp_state->curr_byte = 0;
    comp_state->total_bits = 0;
    comp_state->io_end = 0;

    if(raw_bytes == 0) {
        append_comp_byte(comp_state, (uint8_t)0x00, 8);
        comp_state->io_end = 1;
        return 0;
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
        {1, 4, 8},
        {2, 4, 8},
        {3, 6, 8},
        {3, 6, 8}
    };
    const uint8_t dict_total_size[4][3] = {
        {2,  8,  16},
        {8,  16, 32},
        {18, 36, 48},
        {18, 36, 48}
    };

    /* 0xFF is illegal. */
    const uint8_t comp_byte_size[4] = {1, 2, 0xFF, 3};

    uint16_t i = 0;
    uint8_t header = 0x00;
    uint8_t unique_dict_elem = 0x00;

    for(i = 0; i < 256; i++) {
        frequency[i].index = i;
        frequency[i].freq = 0;
    }
    for(i = 0; i < raw_bytes; i++) {
        frequency[state[i]].freq++;
    }
    qsort(frequency, 256, sizeof(struct freq_matrix), compare);
    
    if(frequency[0].freq == raw_bytes) {
        comp_method = 0;
        dict_elem_code = 3;
        unique_dict_elem = frequency[0].index;

        header = (0x80) | (comp_method << 5) | (dict_elem_code << 3);
        append_comp_byte(comp_state, header, 5);
        append_comp_byte(comp_state, unique_dict_elem, 8);
        
        if(raw_bytes != FULL_STATE_BYTES) {
            append_comp_byte(comp_state, (uint8_t)raw_bytes, 8);
            comp_state->io_end = 1;
        }
        return 1;
    }

    top2_freqs = frequency[0].freq + frequency[1].freq;
    top4_freqs = top2_freqs + frequency[2].freq + frequency[3].freq;
    top6_freqs = top4_freqs + frequency[4].freq + frequency[5].freq;
    top2_6_freqs = top6_freqs - top2_freqs;
    
    index_max_2 = GET_MAX(frequency[0].index, frequency[1].index);
    index_max_4 = GET_MAX(GET_MAX(frequency[2].index, frequency[3].index), index_max_2);
    index_max_6 = GET_MAX(GET_MAX(frequency[4].index, frequency[5].index), index_max_4);

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

    comp_bits[0] = 5 + dict_total_size[0][dict_elem_flags[0]] + top2_freqs * 2 + (raw_bytes - top2_freqs) + (raw_bytes - top2_freqs) * 8;
    comp_bits[1] = 5 + dict_total_size[1][dict_elem_flags[1]] + top4_freqs * 3 + (raw_bytes - top4_freqs) + (raw_bytes - top4_freqs) * 8;
    comp_bits[2] = 5 + dict_total_size[2][dict_elem_flags[2]] + top2_freqs * 3 + top2_6_freqs *4 + (raw_bytes - top6_freqs) + (raw_bytes - top6_freqs) * 8;
    comp_bits[3] = 5 + dict_total_size[3][dict_elem_flags[3]] + top6_freqs * 4 + (raw_bytes - top6_freqs) + (raw_bytes - top6_freqs) * 8;

    if(comp_bits[0] >= raw_bits && comp_bits[1] >= raw_bits && comp_bits[2] >= raw_bits && comp_bits[3] >= raw_bits) {
        header = 0x00;
        append_comp_byte(comp_state, header, 1);
        for(i = 0; i < raw_bytes; i++) {
            append_comp_byte(comp_state, state[i], 8);
        }
        if(raw_bytes != FULL_STATE_BYTES) {
            append_comp_byte(comp_state, (uint8_t)raw_bytes, 8);
            comp_state->io_end = 1;
        }
        return 2;
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
    
    header = (0x80) | (comp_method << 5) | (dict_elem_code << 3);
    /* Padding the header */
    append_comp_byte(comp_state, header, 5);
    uint8_t dict_elem_bits = dict_elem_size[comp_method][dict_elem_code];
    uint8_t dict_elem_left = 8 - dict_elem_bits;
    int8_t freq_pos = 0;
    uint8_t compressed_byte;
    /* Padding the dictionary */
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
        comp_state->io_end = 1;
    }
    return 3;
}

int check_header_validity(const uint8_t comp_method, const uint8_t dict_elem_code) {
    if(comp_method > COMP_METHOD_MAX) {
        return INVALID_HEADER_FLAG;
    }
    if(comp_method == 0) {
        if(dict_elem_code > DICT_ELEM_CODE_MAX_A) {
            return INVALID_HEADER_FLAG;
        }
    }
    else {
        if(dict_elem_code > DICT_ELEM_CODE_MAX_BCD) {
            return INVALID_HEADER_FLAG;
        }
    }
    return 0;
}

int file_decomp_core(FILE *stream, FILE *target, const uint64_t buffer_size_byte, const uint64_t file_size, const uint8_t file_tail[]){
    if(stream == NULL || target == NULL || file_size < 3 || file_tail == NULL || buffer_size_byte < 64) {
        return -1;
    }

    uint16_t i = 0;
    uint16_t last_buffer_size = (file_tail[3] == 0) ? 256 : file_tail[3];
    uint64_t last_state_pos = ((int64_t)(file_size - last_buffer_size - 2) > 0) ? (file_size - last_buffer_size - 2) : 0;
    
    uint16_t state_orig_bytes = 0;
    uint8_t tail_offset = file_tail[2];
    uint8_t last_state_orig_bytes = file_tail[0] << tail_offset | file_tail[1] >> (8 - tail_offset);
    uint8_t comp_flag = 0;
    uint8_t state_buffer[FULL_STATE_BYTES] = {0x00, };
    struct decomp_state decom_state;
    memset(&decom_state, 0, sizeof(struct decomp_state));

    const uint8_t num_dict_elems[4] = {2, 4, 6, 6};
    const uint8_t dict_elem_size[4][3] = {
        {1, 4, 8},
        {2, 4, 8},
        {3, 6, 8},
        {3, 6, 8}
    };
    const uint8_t comp_byte_size[4] = {1, 2, 0xFF, 3};
    uint8_t dict_elems[6] = {0x00,};
    uint8_t dict_elem_index = 0;
    uint8_t byte_comp_flag = 0;
    uint8_t comp_method = 0, dict_elem_code = 0;
    uint8_t *buffer = (uint8_t *)calloc(buffer_size_byte, sizeof(uint8_t));
    if(buffer == NULL) {
        return -3;
    }
    while(1) {
        get_next_bits(buffer, buffer_size_byte, 1, &comp_flag, &decom_state, stream);
        if((decom_state.stream_bytes_curr + decom_state.curr_byte) >= last_state_pos) {
            state_orig_bytes = last_state_orig_bytes;
        }
        else {
            state_orig_bytes = FULL_STATE_BYTES;
        }
        printf("%d \n", state_orig_bytes);
        if(state_orig_bytes == 0) {
            free(buffer);
            return 0;
        }
        if(comp_flag == 0) {
            memset(state_buffer, 0, FULL_STATE_BYTES);
            for(i = 0; i < state_orig_bytes; i++) {
                get_next_bits(buffer, buffer_size_byte, 8, state_buffer + i, &decom_state, stream);
            }
            fwrite(state_buffer, sizeof(uint8_t), state_orig_bytes, target);
            if(state_orig_bytes < FULL_STATE_BYTES) {
                free(buffer);
                return 0;
            }
            continue;
        }
        get_next_bits(buffer, buffer_size_byte, 2, &comp_method, &decom_state, stream);
        get_next_bits(buffer, buffer_size_byte, 2, &dict_elem_code, &decom_state, stream);
        if(check_header_validity(comp_method, dict_elem_code) == INVALID_HEADER_FLAG) {
            free(buffer);
            return INVALID_HEADER_FLAG;
        }
        if(comp_method == 0 && dict_elem_code == 3) {
            memset(state_buffer, 0, FULL_STATE_BYTES);
            uint8_t unique_dict_elem = 0;
            get_next_bits(buffer, buffer_size_byte, 8, &unique_dict_elem, &decom_state, stream);
            for(i = 0; i < state_orig_bytes; i++) {
                state_buffer[i] = unique_dict_elem;
            }
            fwrite(state_buffer, sizeof(uint8_t), state_orig_bytes, target);
            if(state_orig_bytes < FULL_STATE_BYTES) {
                free(buffer);
                return 0;
            }
            continue;
        }

        for(i = 0; i < num_dict_elems[comp_method]; i++) {
            get_next_bits(buffer, buffer_size_byte, dict_elem_size[comp_method][dict_elem_code], dict_elems + i, &decom_state, stream);
        }
        memset(state_buffer, 0, FULL_STATE_BYTES);
        for(i = 0; i < state_orig_bytes; i++) {
            get_next_bits(buffer, buffer_size_byte, 1, &byte_comp_flag, &decom_state, stream);
            if(byte_comp_flag == 0) {
                get_next_bits(buffer, buffer_size_byte, 8, state_buffer + i, &decom_state, stream);
            }
            else {
                if(comp_method == 2) {
                    get_next_bits(buffer, buffer_size_byte, 1, &byte_comp_flag, &decom_state, stream);
                    if(byte_comp_flag == 0) {
                        get_next_bits(buffer, buffer_size_byte, 1, &dict_elem_index, &decom_state, stream);
                    }
                    else {
                        get_next_bits(buffer, buffer_size_byte, 2, &dict_elem_index, &decom_state, stream);
                        dict_elem_index += 2;
                    }
                    if(dict_elem_index >= num_dict_elems[comp_method]) {
                        free(buffer);
                        return INVALID_DATA_TO_DECOMP;
                    }
                    state_buffer[i] = dict_elems[dict_elem_index];
                }
                else {
                    get_next_bits(buffer, buffer_size_byte, comp_byte_size[comp_method], &dict_elem_index, &decom_state, stream);
                    if(dict_elem_index >= num_dict_elems[comp_method]) {
                        free(buffer);
                        return INVALID_DATA_TO_DECOMP;
                    }
                    state_buffer[i] = dict_elems[dict_elem_index];
                }
            }
        }
        fwrite(state_buffer, sizeof(uint8_t), state_orig_bytes, target);
        if(state_orig_bytes < FULL_STATE_BYTES) {
            free(buffer);
            return 0;
        }
    }
    return 0;
}

int padding_comp_obuffer(const struct bcomp_state *comp_state, struct bcomp_obuffer *output_buffer) {
    if(comp_state == NULL || output_buffer == NULL) {
        return -1;
    }
    memset(output_buffer->bytes_array, 0, 257 * sizeof(uint8_t));
    output_buffer->io_end = comp_state->io_end;
    output_buffer->bytes_valid = 0;
    //uint8_t initial = 0xFF;
    uint16_t i = 0;

    uint8_t tail_byte_prev = output_buffer->prev_tail; 
    uint8_t tail_bits_prev = output_buffer->prev_tail_high_bits;
    uint16_t total_bits = tail_bits_prev + comp_state->total_bits;
    uint8_t tail_bits_new = total_bits % 8;
    uint16_t total_bytes = total_bits / 8;

    output_buffer->bytes_array[0] = tail_byte_prev | (comp_state->bytes[0] >> tail_bits_prev);
    i++;

    while(i < total_bytes) {
        output_buffer->bytes_array[i] = (comp_state->bytes[i-1] << (8 - tail_bits_prev)) | (comp_state->bytes[i] >> tail_bits_prev);
        i++;
    }

    output_buffer->prev_tail_high_bits = tail_bits_new;
    output_buffer->bytes_valid = total_bytes;
    if(output_buffer->io_end == 0) {
        output_buffer->prev_tail = (comp_state->bytes[i-1] << (8 - tail_bits_prev)) | (comp_state->bytes[i] >> tail_bits_prev);
    }
    else {
        output_buffer->bytes_array[i] = (comp_state->bytes[i-1] << (8 - tail_bits_prev)) | (comp_state->bytes[i] >> tail_bits_prev);
        output_buffer->bytes_valid++;
    }
    return 0;
}

int fwrite_comp(FILE *file_p, const struct bcomp_obuffer *output_buffer) {
    if(file_p == NULL) {
        return -1;
    }
    if(fwrite(output_buffer->bytes_array, sizeof(uint8_t), output_buffer->bytes_valid, file_p) != output_buffer->bytes_valid) {
        return -3;
    }
    if(output_buffer->io_end) {
        uint8_t last_state_byte = (uint8_t)(output_buffer->bytes_valid);
        fwrite(&(output_buffer->prev_tail_high_bits), sizeof(uint8_t), 1, file_p);
        fwrite(&last_state_byte, sizeof(uint8_t), 1, file_p);
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
    uint8_t ingest_buffer[FULL_STATE_BYTES] = {0x00, };
    struct bcomp_state comp_state;
    struct bcomp_obuffer output_buffer;
    int8_t err_flag = 0, fwrite_flag = 0;
    memset(&comp_state, 0, sizeof(struct bcomp_state));
    memset(&output_buffer, 0, sizeof(struct bcomp_obuffer));
    size_t bytes_read = 0;
    while(1) {
        bytes_read = fread(&ingest_buffer, sizeof(uint8_t), FULL_STATE_BYTES, filep_s);
        if(compress_core(ingest_buffer, bytes_read, &comp_state) < 0) {
            err_flag = -5;
            goto close_and_return;
        }
        if(padding_comp_obuffer(&comp_state, &output_buffer) != 0) {
            err_flag = -7;
            goto close_and_return;
        }
        fwrite_flag = fwrite_comp(filep_t, &output_buffer);
        if(fwrite_flag < 0) {
            err_flag = -9;
            goto close_and_return;
        }
        else if(fwrite_flag == 1) {
            fclose(filep_s);
            fclose(filep_t);
            return 0;
        }
        if(bytes_read != FULL_STATE_BYTES) {
            goto close_and_return;
        }
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
    uint8_t tail_info[4] = {0x00, };
    uint64_t read_buffer_size = 0;
#ifdef _WIN32
    _fseeki64(filep_s, -4, SEEK_END);
    int64_t file_size = _ftelli64(filep_s) + 4;
#else
    fseeko(filep_s, -4, SEEK_END);
    int64_t file_size = ftello(filep_s) + 4;
#endif
    if(fread(tail_info, sizeof(uint8_t), 4, filep_s) != 4) {
        fclose(filep_s);
        return INVALID_TAIL_INFO;
    }
    rewind(filep_s);
    if(file_size > 0x10000) {
        read_buffer_size = 8192;
    }
    else {
        read_buffer_size = 1024;
    }
    if(file_size < COMP_FILE_MIN_SIZE) {
        fclose(filep_s);
        return INVALID_FILE_TO_DECOMP;
    }
    if(tail_info[2] > 7) {
        fclose(filep_s);
        return INVALID_TAIL_INFO;
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
    int err_flag = file_decomp_core(filep_s, filep_t, read_buffer_size, file_size, tail_info);
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
    snprintf(comp_filename, 2048, "%s.bc", argv[3]);
    if(strcmp(argv[1], "-c") == 0) {
        run_flag = file_bcomp(argv[2], comp_filename);
        printf("INFO: Compressed file %s to %s . Return Value: %d.\n", argv[2], comp_filename, run_flag);
    }
    else {
        run_flag = file_bcomp_decomp(argv[2], argv[3]);
        if(run_flag != 0) {
            printf("ERRO: Decompression failed. Error Code: %d.\n", run_flag);
        }
        else {
            printf("INFO: Decompressed file %s to %s .\n", argv[2], argv[3]);
        }
    }
    printf("Repository: https://github.com/zhenrong-wang/bcomp \n");
    return 0;
}
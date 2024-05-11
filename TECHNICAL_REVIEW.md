# TR: BCOMP - A Simple, Possible Algorithm of Lossless Compression

[Author: Zhenrong WANG](https://github.com/zhenrong-wang)

# 0. Abstract

This article described a simple, bit-based, possible algorithm of lossless compression. 

# 1. Backgrounds

Given a file or a data block, compress it without losing any information (aka, lossless compression).

# 2. Algorithm Description

## 2.1 Overview

This proposed algorithm focuses on binary level, not text level. The unit to process is 256 bytes (named as `state`).

For any raw data block, the algorithm works with the flow as below:

- Ingest 256 bytes to assemble a `state[256]`
- For each `state[256]`, scan every byte and calculate the frequency of each byte ranges from `0x00` to `0xFF`.
- Sort the frequency matrix to get the `Top N` frequencies and their corresponding index in `0x00` to `0xFF`.
- Recode the bytes according to the sorted frequencies.
- Output the compressed data block (named as `bcomp_state`).
- Ingest next 256 bytes.

For the last `state`, we need another 8 bit to record its actual size if it does not contain 256 bytes.

## 2.2 Details

For each `state` with 256 bytes, the **sorted** frequency matrix would be:

```
sorted_freq[0]   |  index: 0xMM  | frequncy: 0xNNN *highest_frequency
sorted_freq[1]   |  index: 0xMM  | frequncy: 0xNNN
...
sorted_freq[255] |  index: 0xMM  | frequncy: 0xNNN *lowest_frequency
```
The `index` ranges in `[0, 255]`, while the `frequency` of each index ranges in `[0, 256]`.

### 2.1 Uncompressible State

A `state` might not be compressible (details in next section). We need to use 1 bit, that is, `0` as the header of an uncompressible `state`.

In this case, the compression ratio for this `state` would be: `(256 * 8 + 1) / (256 * 8) = 1.00048828125`. 

It is not compressed, instead, it increased the size by a little bit due to the introduced header.

### 2.2 Compressible State

For a compressible `state`, first of all, we need 1 bit, that is, `1` as the header.

Then, we can use several ways to compress it based on the **sorted** frequency statistics. 

Let's use:

`Top(N) = sorted_freq[0].frequncy + ... + sorted_freq[N-1].frequency`

`Top(M, N) = Top(N) - Top(M)`

We can use either method of the 4:

- A. Compress the `Top[2]` bytes to 1 bit. Leave the others as 8 bits.
- B. Compress the `Top[4]` bytes to 2 bits. Leave the others as 8 bits.
- C. Compress the `Top[2]` bytes to 1 bit, compress the `Top[2, 6]`to 2 bits. Leave the others as 8 bits.
- D. Compress the `Top[6]` bytes to 3 bits. Leave the others as 8 bits.

We need to record the original 8 bits(1 byte) of the compressed bytes. A dictionary is needed. As below:

`0xMM 0xNN 0xPP 0xQQ ... `

Note that the element of dictionary doesn't necessarily require 8 bits, we can use another 1 bit to indicate the real size.

With all the methodology above, we can now design the header of a compressed `state`:

```
FLAG    METHOD   DICT_ELEM_SIZE
1       xx       x
```
The header length is fixed as 4 bits.

The remaining length would be variable. 

First sub-block would be the dictionary. Here is the table:

```
Method  METHOD  DICT_ELEM_SIZE  #Elems_of_dict  Elem_size   Dict_length
A       00      0               2               4           8
A       00      1               2               8           16

B       01      0               4               4           16
B       01      1               4               8           32

C       10      0               6               4           24
C       10      1               6               8           48

D       11      0               6               4           24
D       11      1               6               8           48

```
The next sub-block would be the compressed bytes with variable length (not 8 bits). 

Again, there might be many uncompressible bytes (low-frequency bytes). Each uncompressible bytes would be expanded to 9 bits because a header 0 is needed to indicate the following 8 bits are not compressed.

For compressible bytes (high-frequency bytes recorded in the dictionary), we put one bit, that is `1` to indicate the compression. The actual length of the compressed byte would be reflected by the `METHOD` code of this `state`.

```
Method  METHOD  COMPRESSED_BITS_WITH_HEADER
A       00      2
B       01      3
C       10      3 for Top(2), 4 for Top(2,6)
D       11      4
```

For each `state`, we calculate the possible compression ratio of the 4 methods above and determine the real method adopted and put it to the header as METHOD code. For the DICT_ELEM_SIZE, we calculate the maximum size of the index of `Top(N)` and determin the size and the code in the header.

If all the possible compression ratios are greater than 1.0, we just give up and tag it as "uncompressible" with a one-bit header `0`, and move on to the next `state`.

With all the efforts above, this method would be implementable.


# 3. Summary and Future Work

This method is simple, feasible, implementable, and effective. I'll implement it in C and keep this repository updated.

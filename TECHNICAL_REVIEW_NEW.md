# TR: PCOMP - A Pattern-Based Algorithm of Lossless Compression

[Author: Zhenrong WANG](https://github.com/zhenrong-wang)

# 0. Abstract

This article described a simple, pattern-based, possible algorithm of lossless compression. 

# 1. Backgrounds

Given a file or a data block, compress it without losing any information (aka, lossless compression).

# 2. Algorithm Description

## 2.1 Basic Logic

One possible way for lossless compression is:

1. Record the patterns appeared
2. Encode the patterns
3. Replace the actual pattern (byte sequences) with the shorter pattern codes

This proposed algorithm follows this basic logic.

## 2.2 Details

The whole algorithm contains a dictionary and the encoded patterns. Main steps:

1. Filter all unique bytes by their first appereance as the base dictionary
2. Expand the dictionary while scanning and encoding the patterns
3. Write down the final dictionary and the encoded patterns

For decompression:

1. Read the dictionary at the head of the compressed file/stream
2. Read the encoded patterns at bit level and parse the bit ingested
3. Replace the encoded bits with the original patterns.

Let's take a sample text for an example:

```A cat catches a rat``` with the size of `19 * 8 = 152 bits`

### 2.2.1 Filter Unique Bytes:

```A \space c a t h e s r```, with the size of `9 * 8 = 72 bits`. 

The Unique dictionary: `{'A', ' ', 'c', 'a', 't', 'h', 'e', 's', 'r'}`;

### 2.2.2 Build the Expanded Dictionary:

Scan the original bytes to build the dictionary.

```
A:   
Dict: Unchanged 

A :
Dict: Unchanged

A c:
Dict: Unchanged

A ca:
Dict: Unchanged

A cat:
Dict: Unchanged

A cat cat:
A new pattern `t ca` found. Add a new item `100 001 010 011` to the expanded dict using the index.

A cat catc:
A new pattern `tc` found. Add a new item `100 010` to the expanded dict using the index.

A cat catch:
Dict: unchanged

A cat catche:
Dict: unchanged

A cat catches:
Dict: unchanged

A cat catches a :
A new pattern `s a ` found. Add a new item `0111 0001 0011 0001` to the expanded dict using the index.

A cat catches a r:
Dict: unchanged

A cat catches a rat:
A new pattern `rat` found. Add a new item `1000 0011 0100` to the expanded dict using the index: 
```

Final Dictionary:

Unique: ```{'A', ' ', 'c', 'a', 't', 'h', 'e', 's', 'r'}``` with 72 bits

Expanded: 
```
{
011    100 001 010 011    100 010

       111 001 011 001

100    1000 0011 0100
}
```
with 48 bits.

### 2.2.3 Encoding

With the dictionary above, we can start encoding the original bytes. At each position, we use:

- `00` as an indicator as the current unique byte
- `01` as an indicator to move to the next unique byte
- `1` as an indecator to find from the expanded dictionary

The original bytes `A cat catches a rat` would be encoded to:

```
A   ' '  c    a    t' ' ca   tc     h    e    s' 'a' '   rat
00  01   01   01   10        11     01   01   10         10
```

with 20 bits, compression ratio is `153 / 20 = 7.6` .

Total bits including the dictionary would be `140 bits`.

Notice that the Unique dictionary can be compressed further to `9 * 7 = 63` bits. The final compressed total bits would be `131 bits`.

The dictionary would be more and more reusable along with the stream of the original data, therefore, the compression ratio is expected to be much better than that in this demo.


# 3. Summary and Future Work

This method is simple, feasible, implementable, and effective. I'll implement it in C and keep this repository updated.
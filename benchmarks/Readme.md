For benchmarks.py, on Linux, Python 3.13, we have - 

```
[ HS256 ]
Toke Encode              :     2.63 µs/op
PyJWT Encode             :     7.94 µs/op
Toke Decode              :     5.19 µs/op
PyJWT Decode             :     9.53 µs/op
 >>> Speedup: Enc: 3.0x | Dec: 1.8x

[ RS256 ]
Toke Encode              :   500.51 µs/op
PyJWT Encode             : 28118.72 µs/op
Toke Decode              :    31.09 µs/op
PyJWT Decode             :    37.17 µs/op
 >>> Speedup: Enc: 56.2x | Dec: 1.2x

[ ES256 ]
Toke Encode              :    26.85 µs/op
PyJWT Encode             :    60.92 µs/op
Toke Decode              :    48.72 µs/op
PyJWT Decode             :    91.48 µs/op
 >>> Speedup: Enc: 2.3x | Dec: 1.9x

[ EdDSA ]
Toke Encode              :    27.41 µs/op
PyJWT Encode             :    68.55 µs/op
Toke Decode              :    38.75 µs/op
PyJWT Decode             :    93.76 µs/op
 >>> Speedup: Enc: 2.5x | Dec: 2.4x

[ ES512 ]
Toke Encode              :   196.79 µs/op
PyJWT Encode             :   378.55 µs/op
Toke Decode              :   286.33 µs/op
PyJWT Decode             :   438.69 µs/op
 >>> Speedup: Enc: 1.9x | Dec: 1.5x

[ ES256K ]
Toke Encode              :   374.93 µs/op
PyJWT Encode             :        N/A
Toke Decode              :   181.72 µs/op
PyJWT Decode             :        N/A

[ ML-DSA-65 ]
Toke Encode              :   391.09 µs/op
PyJWT Encode             :        N/A
Toke Decode              :    85.80 µs/op
PyJWT Decode             :        N/A
```

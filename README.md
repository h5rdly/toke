![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-darkgreen?style=flat&logo=python&logoColor=blue)

# Toke

**Rust-backed JWT**

##  Speed

[Simple benchmark](https://github.com/h5rdly/toke/blob/main/benchmarks/benchmarks.py)

```
HS256
Enc: 3.0x | Dec: 1.8x

RS256
Enc: 56.2x | Dec: 1.2x

ES256
Enc: 2.3x | Dec: 1.9x

EdDSA
 Enc: 2.5x | Dec: 2.4x

ES512
Enc: 1.9x | Dec: 1.5x
```

See (and suggest!) more benchmarks under [benchmarks](https://github.com/h5rdly/toke/blob/main/benchmarks/)

##  Size

The Rust `.so` file on linux is ~3.5Mb, no external dependencies.

##  Installation

`pip install webtoken`

Developed on Linux / Python 3.13, currently can't attest to other platforms.

##  Usage

1. PyJWT Style (Drop-in Replacement)

```python
import toke

key = "secret"
payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
token = toke.encode(payload, key, algorithm="HS256")

decoded = toke.decode(token, key, algorithms=["HS256"])
print(decoded)
```

2. Toke style - in design

3. Asyncio variants

```python
import toke

# The rust based encode/decode release the GIL
# You can send them away on asyncio.to_thread(), or use the provided wrappers

payload = {"name": "Bob"}
token = await toke.encode_async(payload, "secret", algorithm="HS256")

decoded = await toke.decode_async(token, "secret", algorithms=["HS256"])
print(decoded)
# {'name': 'Bob'}
```

##  Compatibility

Effort is made to make toke as compatible as possible with [PyJWT](https://github.com/jpadilla/pyjwt). To that effect, changes are made to make the relevant tests from the extensive PyJWT [test suite](https://github.com/jpadilla/pyjwt/tree/master/tests) pass. 

##  Crypto

Toke is backed by [jsonwebtoken](https://github.com/Keats/jsonwebtoken) and [aws-lc-rs](https://github.com/aws/aws-lc-rs).


### Supported algorithms

Via jsonwebtoken - 
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512

Via aws-lc-rs - 
- ES512
- ES256K
- ML-DSA-65

##  Fun Facts

- Using the Rust Crypto backend with jsonwebtoken made the binary around ~1Mb on linux. However, RSA decoding was slower than using PyJWT. Thus, we switched to aws-lc-rs.  

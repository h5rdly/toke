# Toke

**A Rust-backed JWT library for Python**

## 📦 Size

The Rust `.so` file on linux is ~3.9Mb, no external dependencies.

## 🚀 Speed

Simple benchmark - 

https://github.com/h5rdly/toke/blob/main/benchmarks/benchmarks.py

See (or suggest!) more benchmarks under /benchmarks

## 📦 Installation

`pip install pytoke`

Pre-compiled wheels are available for Linux (glibc and musl), Windows.

## 💻 Usage

1. PyJWT Style (Drop-in Replacement)Toke mimics the PyJWT API, so migration is usually just an import change.

```python
import toke

key = "secret"
payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
token = toke.encode(payload, key, algorithm="HS256")

decoded = toke.decode(token, key, algorithms=["HS256"])
print(decoded)
```

## 🤝 Compatibility

Effort is made to make toke as compatible as possible with [PyJWT](https://github.com/jpadilla/pyjwt). To that effect, changes are made to make the relevant tests from the extensive PyJWT [test suite](https://github.com/jpadilla/pyjwt/tree/master/tests) pass. 

## 🛡️ Crypto

Toke is backed by [jsonwebtoken](https://github.com/Keats/jsonwebtoken) and [aws-lc-rs](https://github.com/aws/aws-lc-rs).


Supported algorithms

Via jsonwebtoken - 
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512

Via aws-lc-rs - 
- ES512
- ML-DSA-65

- 
## 🧠 Fun Facts

- Using the Rust Crypto backend with jsonwebtoken made the binary around ~1Mb on linux. However, RSA decoding was slower than using PyJWT.  

# Toke

**A Rust-backed JWT library for Python**

## 📦 Size

The .so file on linux is ~3.6Mb, no external dependencies.


## 🚀 Speed

Simple benchmark - 

https://github.com/h5rdly/toke/blob/main/benchmarks/benchmarks.py
```

See (or suggest!) more benchmarks under /benchmarks


## 🛡️ Security

Toke is backed by [jsonwebtoken](https://github.com/Keats/jsonwebtoken) and [aws-lc-rs](https://github.com/aws/aws-lc-rs).


Supported algorithms

Via jsonwebtoken - 
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512

## 📦 Installation

`pip install pytoke`

Pre-compiled wheels are available for Linux (glibc and musl), Windows.


## 💻 Usage

1. PyJWT Style (Drop-in Replacement)Toke mimics the PyJWT API, so migration is usually just an import change.Pythonimport toke

```python
# Encoding
key = "secret"
payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
token = toke.encode(payload, key, algorithm="HS256")

# Decoding
decoded = toke.decode(token, key, algorithms=["HS256"])
print(decoded)
```

2. Post-Quantum JWTs (ML-DSA)Toke is one of the first libraries to support NIST's finalized Post-Quantum signature standard.

```python
import toke
import os

# ML-DSA keys are currently raw seed bytes (32 bytes)
private_seed = os.urandom(32)

# Public keys are derived (1952 bytes for ML-DSA-65)
# (In a real app, you would load these from a file/KMS)

# Sign with PQ
pq_token = toke.encode(payload, private_seed, algorithm="ML-DSA-65")
```

## 🤝 Compatibility

Effort is made to make toke as compatible as possible with [PyJWT](https://github.com/jpadilla/pyjwt). To that effect, changes are made to make the relevant tests from the extensive PyJWT [test suite](https://github.com/jpadilla/pyjwt/tree/master/tests) pass. 

More in the `/tests` folder [Readme]()


## 🧠 Fun Facts

- Using the Rust Crypto backend with jsonwebtoken made the binary around ~1Mb on linux. However, RSA decoding was slower than using PyJWT.  


### Usage
[todo]

#### PyJWT style


#### Toke Validator style

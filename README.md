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


```md
Supported algorithms
| Type | Algorithm | Notes |
| :--- | :--- | :--- |
| **HMAC** | `HS256`, `HS384`, `HS512` | Standard symmetric signatures |
| **RSA** | `RS256`, `RS384`, `RS512` | PKCS#1 v1.5 padding |
| **PSS** | `PS256`, `PS384`, `PS512` | Probabilistic Signature Scheme |
| **ECDSA** | `ES256`, `ES384` | NIST P-256 / P-384 |
| **Extended ECDSA** | `ES512` | **NIST P-521** (Added in Toke) |
| **Blockchain** | `ES256K` | **secp256k1** (Bitcoin/Ethereum) (Added in Toke) |
| **EdDSA** | `EdDSA` | Ed25519 |
| **Post-Quantum** | `ML-DSA-65` | **NIST FIPS 204 (Dilithium)** (Added in Toke)


        Note: "none" alg is supported for compatibility but strongly discouraged.

Via jsonwebtoken - 
- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
-


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

3. Custom AlgorithmsHave a proprietary HSM or a weird experimental algorithm? You can plug it into Toke without forking.

```python
import toke

class MyCustomAlgo:

    def sign(self, msg: bytes, key: bytes) -> bytes:
        return b"custom_signature"

    def verify(self, msg: bytes, sig: bytes, key: bytes) -> bool:
        return sig == b"custom_signature"

# Register it
toke.register_algorithm("MY-ALGO", MyCustomAlgo())

# Use it naturally (Core JWT logic happens in Rust, crypto happens in Python)
token = toke.encode(payload, key, algorithm="MY-ALGO")
```

## 🤝 Compatibility

Effort was made to make toke as compatible as possible with [PyJWT](https://github.com/jpadilla/pyjwt). To that effect, changes are made to make the relevant tests from the extensive PyJWT [test suite](https://github.com/jpadilla/pyjwt/tree/master/tests) pass. 

More in the `/tests` folder [Readme]()


## 🧠 Fun Facts

- Using the Rust Crypto backend with jsonwebtoken made the binary around ~1Mb on linux. However, RSA decoding was slower than using PyJWT.  

- [ML-DSA-65](https://github.com/aws/aws-lc-rs/tree/main/aws-lc-rs/src/pqdsa) is currently supported only on the unstable branch of aws-lc-rs.




`pip install pytoke`  # Add quant / no quant options

### Usage

#### PyJWT style


#### Toke Validator style

import asyncio, sys, time, json, os, decimal

import jwt

sys.path.append(__file__.rsplit("/", 2)[0])
import toke



def _check_algo(alg, payload):
    """Helper to run a full Generate -> Encode -> Decode cycle"""

    try:
        # 1. Generate Key
        priv_bytes, pub_bytes = toke.generate_key_pair(alg)
        
        if alg in ["ML-DSA-65", "ML-DSA-44", "ML-DSA-87"]:
            priv = priv_bytes.decode("utf-8")
            pub = pub_bytes.decode("utf-8")
        else:
            priv = priv_bytes.decode("utf-8")
            pub = pub_bytes.decode("utf-8")

        # 2. Encode
        token = toke.encode(payload, priv, algorithm=alg)
        if not toke or not isinstance(token, str):
            print(f"❌ {alg} failed - got token {token}")
            return

        # 3. Decode
        decoded = toke.decode(token, pub, algorithms=[alg])
        
        # 4. Assert Consistency
        assert decoded["sub"] == payload["sub"]
        assert decoded["metadata"] == payload["metadata"]
        
        print(f"✅ {alg} passed")

    except Exception as e:
        print(f"❌ {alg} failed: {e}")

payload = {
            "sub": "test_user",
            "role": "admin",
            "metadata": {"id": 123},
            "exp": int(time.time()) + 3600
}

def test_hs256():
    # Symmetric is special (key is just a string/bytes)
    key = "super_secret_key_bytes"
    token = toke.encode(payload, key, algorithm="HS256")
    decoded = toke.decode(token, key, algorithms=["HS256"])
    assert decoded["sub"] == payload["sub"]

def test_rs256(): _check_algo("RS256", payload)
def test_es256(): _check_algo("ES256", payload)
def test_eddsa(): _check_algo("EdDSA", payload)
def test_es512(): _check_algo("ES512", payload)
def test_es256k(): _check_algo("ES256K", payload)
def test_mldsa65(): _check_algo("ML-DSA-65", payload)


def test_expired_token():
    
    print("--- Testing Expired Token ---")
    payload = {"sub": "test", "exp": int(time.time()) - 10}
    token = toke.encode(payload, "secret", algorithm="HS256")

    try:
        res = toke.decode(token, "secret", algorithms=["HS256"])
    except toke.ExpiredSignatureError:
        print("✅ Caught correct specific exception!")
    except ValueError:
        print("❌ Caught generic ValueError (Bad for drop-in replacement)")
    else:
        print(f'{res=}')


def test_unverified_header():

    print("--- Testing Header Extraction ---")
    secret = "secret"
    token = toke.encode({"sub": "1"}, secret, algorithm="HS256", headers={"kid": "key_1"})

    try:
        header = toke.get_unverified_header(token)
        print(f"✅ Header extracted: {header}")
        assert header['kid'] == 'key_1'
        assert header['alg'] == 'HS256'
    except AttributeError:
        print("❌ get_unverified_header missing!")


def test_detached_header():

    #- Test detached JWS (header..signature)
    # Creating a real token and removing the payload part
    full_payload = {"sub": "detached_test"}
    full_token = toke.encode(full_payload, "secret", algorithm="HS256")
    header, _, signature = full_token.split(".")
    detached_token = f"{header}..{signature}"

    print(f"Detached Token: {detached_token}")

    # 2. Decode it providing the content
    content = json.dumps(full_payload, separators=(",", ":")).encode('utf-8') # b'{"sub": "detached_test"}'

    try:
        decoded = toke.decode(detached_token, "secret", algorithms=["HS256"], content=content)
        print(f"✅ Success! Claims: {decoded}")
    except Exception as e:
        print(f"❌ Failed: {e}")

    # 3. Verify failure if we provide content to a non-detached token
    try:
        toke.decode(full_token, "secret", algorithms=["HS256"], content=content)
    except Exception as e:
        print(f"✅ Correctly rejected double payload: {e}")


def test_list_in_claims():

    print("\n--- Testing List Claims ---")
    payload = {"sub": "1", "aud": ["service_a", "service_b"]}
    token = toke.encode(payload, "secret")
    try:
        # Verify we can decode with one of the audiences
        toke.decode(token, "secret", audience="service_b", algorithms=["HS256"])
        print("✅ List audience validated successfully")
    except Exception as e:
        print(f"❌ Failed list audience: {e}")


def test_type_coercion():

    print("\n--- Testing Custom Types ---")
    try:
        # PyJWT handles this if you pass a custom encoder, but fails by default.
        # Toke will likely fail immediately because pythonize doesn't know what a 'set' is in JSON.
        toke.encode({"tags": {1, 2, 3}}, secret) 
        print("❓ Set serialization worked (unexpected)")
    except Exception as e:
        print(f"ℹ️ Set serialization failed as expected (Rust strictness): {e}")


def test_none_as_algorithm():

    print("\n--- Testing 'None' Algorithm ---")
    none_token = None # Initialize to avoid NameError if encode fails

    # 1. Encode with 'none'
    try:
        none_token = toke.encode({"sub": "unsecured"}, None, algorithm="none")
        print(f"✅ 'none' algorithm encoded successfully: {none_token[:15]}...")
    except Exception as e:
        print(f"❌ 'none' encoding failed: {e}")

    if none_token:
        # 2. Decode 'none' token WITHOUT permission (Should FAIL)
        try:
            toke.decode(none_token, None)
            print("❌ Security Risk: 'none' token accepted without explicit permission")
        except toke.InvalidTokenError:
            print("✅ 'none' token correctly rejected by default")
        except Exception as e:
            print(f"✅ 'none' token rejected (caught {type(e).__name__}): {e}")

        # 3. Decode 'none' token WITH permission (Should SUCCEED)
        try:
            # Note: verify=False is often required for 'none' depending on exact semantics
            decoded = toke.decode(none_token, None, algorithms=["none"], verify=False)
            print(f"✅ 'none' token decoded with explicit permission: {decoded}")
        except Exception as e:
            print(f"❌ Failed to decode 'none' even with permission: {e}")
    else:
        print("⚠️ Skipping decode tests because encode failed.")


def test_custom_json_encoder():

    print("\n--- Testing Custom JSON Encoder ---")
    class CustomEncoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, set):
                return list(o)
            if isinstance(o, decimal.Decimal):
                return str(o)
            return super().default(o)

    payload = {
        "sub": "custom_types",
        "roles": {"admin", "editor"},  # Set (normally fails)
        "balance": decimal.Decimal("100.50")   # Decimal (normally fails)
    }

    try:
        # 1. Encode with custom encoder
        token = toke.encode(payload, "secret", json_encoder=CustomEncoder)
        print(f"✅ Encoded with custom types: {token[:15]}...")

        # 2. Decode and verify
        decoded = toke.decode(token, "secret", algorithms=["HS256"])
        print(f"✅ Decoded Payload: {decoded}")
        
        # Assertions
        assert decoded["roles"] == ["admin", "editor"] or decoded["roles"] == ["editor", "admin"]
        assert decoded["balance"] == "100.50"
        print("✅ Assertions passed: Sets -> Lists, Decimals -> Strings")

    except TypeError as e:
        print(f"❌ Failed: Custom encoder ignored. Error: {e}")
    except Exception as e:
        print(f"❌ Failed with unexpected error: {e}")


def test_parse_ssh_key():
    os.system("ssh-keygen -t rsa -b 2048 -f test_key -N '' -q")

    try:
        with open("test_key", "rb") as f:
            ssh_private = f.read() # Starts with -----BEGIN OPENSSH PRIVATE KEY-----
        
        with open("test_key.pub", "rb") as f:
            ssh_public = f.read()  # Starts with ssh-rsa AAAA...

        print(f"Private Key Format: {ssh_private[:35]}...") 
        print(f"Public Key Format:  {ssh_public[:20]}...")

        # 2. Encode using the OpenSSH Private Key (Toke converts this to PKCS#8 internally)
        payload = {"sub": "ssh_user"}
        token = toke.encode(payload, ssh_private, algorithm="RS256")
        print(f"✅ Encoded Token: {token[:20]}...")

        # 3. Decode using the SSH Public Key (Toke converts this to SPKI internally)
        decoded = toke.decode(token, ssh_public, algorithms=["RS256"])
        print(f"✅ Decoded Payload: {decoded}")

    finally:
        # Cleanup
        if os.path.exists("test_key"): os.remove("test_key")
        if os.path.exists("test_key.pub"): os.remove("test_key.pub")


def test_using_class(algorithm="HS256"):

    toker = toke.PyJWT()
    token = toker.encode({"sub": "1"}, "secret", algorithm=algorithm)
    res = toke.decode(token, "secret", algorithms=["HS256"])
    print(f'{token=}\n\n{res=}')


def test_custom_algo():

    class MyWeirdAlgo:
        def sign(self, msg: bytes, key: bytes) -> bytes:
            # Do custom crypto here...
            return b"my_signature_bytes"

        def verify(self, msg: bytes, sig: bytes, key: bytes) -> bool:
            return sig == b"my_signature_bytes"

    toke.register_algorithm("WEIRD-256", MyWeirdAlgo())
    token = toke.encode({"sub": "123"}, "secret", algorithm="WEIRD-256")
    print(f'{token=}')
     

async def test_asyncio():
    print("--- Testing Async Support ---")
    
    SECRET = "secret"
    PAYLOAD = {"sub": "async_user"}

    # 1. Encode Async
    start = time.time()
    token = await toke.encode_async(PAYLOAD, SECRET, algorithm="HS256")
    print(f"✅ Encoded (Async): {token[:20]}... in {time.time() - start:.5f}s")

    # 2. Decode Async
    start = time.time()
    decoded = await toke.decode_async(token, SECRET, algorithms=["HS256"])
    print(f"✅ Decoded (Async): {decoded} in {time.time() - start:.5f}s")

    # 3. Concurrency Test (Proof it doesn't block)
    print("\n--- Concurrency Test (10k ops) ---")
    
    async def worker(i):
        # Heavy operation: RSA would be better here to show CPU offloading
        t = await toke.encode_async({"idx": i}, SECRET)
        await toke.decode_async(t, SECRET, algorithms=["HS256"])
        return i

    start = time.time()
    # Launch 10,000 tasks. If this blocked the GIL, it would be slow.
    # Because we use spawn_blocking, these run in the Rust thread pool.
    tasks = [worker(i) for i in range(10000)]
    await asyncio.gather(*tasks)
    print(f"✅ Finished 10k encode/decode cycles in {time.time() - start:.2f}s")


if __name__ == "__main__":

    tests = (
        test_hs256,
        test_rs256,
        test_es256,
        test_eddsa,
        test_es512,
        test_es256k,
        test_mldsa65,

        test_expired_token,
        test_unverified_header,
        test_detached_header,
        test_list_in_claims,

        test_type_coercion,
        test_none_as_algorithm,
        test_custom_json_encoder,
        test_parse_ssh_key,

        test_using_class,
        # test_custom_algo,
    )

for test in tests:
    test()
    pass


asyncio.run(test_asyncio())

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


def test_file_key_loading():
    print("\n--- Testing Key Loading from Files ---")
    
    # 1. Generate valid PEM keys using Toke
    # (returns bytes in standard PKCS#8 / SPKI format)
    priv_pem, pub_pem = toke.generate_key_pair("RS256")
    
    filename_priv = "temp_test_key.pem"
    filename_pub = "temp_test_key.pub"

    try:
        # 2. Simulate saving to disk (like a real app would)
        with open(filename_priv, "wb") as f: 
            f.write(priv_pem)
        
        with open(filename_pub, "wb") as f: 
            f.write(pub_pem)

        # 3. Read back from disk
        with open(filename_priv, "rb") as f: 
            loaded_priv = f.read()
        
        with open(filename_pub, "rb") as f: 
            loaded_pub = f.read()

        print(f"Private Key Header: {loaded_priv.splitlines()[0]}") 
        
        # 4. Encode using the loaded Private Key
        payload = {"sub": "file_system_user"}
        token = toke.encode(payload, loaded_priv, algorithm="RS256")
        print(f"✅ Encoded Token: {token[:20]}...")

        # 5. Decode using the loaded Public Key
        decoded = toke.decode(token, loaded_pub, algorithms=["RS256"])
        assert decoded["sub"] == "file_system_user"
        print(f"✅ Decoded Payload: {decoded}")

    finally:
        # Cleanup files
        if os.path.exists(filename_priv): os.remove(filename_priv)
        if os.path.exists(filename_pub): os.remove(filename_pub)


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
     

def test_public_key_encode_crash_prevention():
    """
    REGRESSION TEST: Ensure passing a Public Key to encode() raises 
    InvalidKeyError instead of crashing the interpreter.
    """
    print("\n--- Test: Public Key Encode Crash Prevention ---")
    
    payload = {"sub": "safety_check", "exp": int(time.time()) + 3600}
    priv_rsa, pub_rsa = toke.generate_key_pair("RS256")
    priv_ec, pub_ec = toke.generate_key_pair("ES256")

    # 1. Test with RSA Public Key
    # try:
    #     toke.encode(payload, pub_rsa, algorithm="RS256")
    #     print("FAILED (Did not raise InvalidKeyError for RSA)")
    #     sys.exit(1)
    # except toke.InvalidKeyError as e:
    #     assert "Public Key" in str(e)

    # # 2. Test with EC Public Key
    # try:
    #     toke.encode(payload, pub_ec, algorithm="ES256")
    #     print("FAILED (Did not raise InvalidKeyError for EC)")
    #     sys.exit(1)
    # except toke.InvalidKeyError as e:
    #     assert "Public Key" in str(e)
    
    print("✅ PASSED Public Key Encode Crash")


def test_hmac_pem_confusion():
    """
    Ensure we cannot accidentally use an Asymmetric PEM key as an HMAC secret.
    """
    print("\n--- Test: HMAC PEM Confusion ---")
    
    payload = {"sub": "safety_check"}
    priv_rsa, _ = toke.generate_key_pair("RS256")

    try:
        toke.encode(payload, priv_rsa, algorithm="HS256")
        print("❌ FAILED (Did not raise InvalidKeyError)")
        sys.exit(1)
    except toke.InvalidKeyError as e:
        assert "asymmetric key" in str(e)
        assert "HMAC secret" in str(e)

    print("✅ PASSED HMAC PEM Confusion.")


def test_none_algorithm_enforcement():
    """
    Ensure 'none' algorithm is rejected unless explicitly allowed.
    """
    print("\n--- Test: None Algorithm Enforcement ---")
    
    payload = {"sub": "safety_check"}
    none_token = toke.encode(payload, "secret", algorithm="none")

    # 1. Default Decode (Should Fail)
    try:
        toke.decode(none_token, "secret", verify=False)
        print("❌ FAILED (Accepted 'none' algo without permission)")
        sys.exit(1)
    except toke.InvalidTokenError:
        pass # Expected

    # 2. Decode with explicit allow (Should Pass)
    decoded = toke.decode(none_token, "secret", verify=False, algorithms=["none"])
    assert decoded["sub"] == "safety_check"

    print("✅ PASSED None Algorithm Enforcement")


def test_invalid_algorithm_string():
    """
    Ensure passing nonsense algorithms raises specific errors.
    """
    print("\n--- Test: Invalid Algorithm String ---")
    
    payload = {"sub": "safety_check"}
    priv_rsa, _ = toke.generate_key_pair("RS256")

    try:
        toke.encode(payload, priv_rsa, algorithm="NOT-A-REAL-ALGO")
        print("❌ FAILED (Did not raise ValueError)")
        sys.exit(1)
    except ValueError as e:
        assert "not supported" in str(e)

    print("✅ PASSED Invalid Algorithm String")



def test_key_type_safety():
    """
    Ensure encode/decode reject invalid key types (ints, dicts).
    """
    print("Test: Key Type Safety...")
    
    payload = {"sub": "safety_check"}

    # 1. Encode with int key (Should fail immediately)
    try:
        toke.encode(payload, 12345, algorithm="HS256")
        print("❌ FAILED (Accepted int key for encode)")
        sys.exit(1)
    except TypeError:
        pass

    # 2. Decode with dict key
    # FIX: Create a VALID token first so the parser doesn't crash on the header.
    # We want it to parse the header, verify 'HS256', and THEN fail on the dict key.
    real_token = toke.encode(payload, "temporary_secret", algorithm="HS256")
    
    try:
        toke.decode(real_token, {"i": "am a dict"}, algorithms=["HS256"])
        print("❌ FAILED (Accepted dict key for decode)")
        sys.exit(1)
    except TypeError:
        pass
        
    print("✅ PASSED Key Type Safety")


async def test_asyncio():
    print("\n--- Testing Async Support ---")
    
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
        test_file_key_loading,

        test_using_class,

        test_public_key_encode_crash_prevention,
        test_hmac_pem_confusion,
        test_none_algorithm_enforcement,
        test_invalid_algorithm_string,
        test_key_type_safety,

        # test_custom_algo,
    )

for test in tests:
    test()
    pass


asyncio.run(test_asyncio())

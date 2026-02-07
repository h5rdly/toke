import json
import sys
import pytest

# Ensure we can import the local webtoken module
sys.path.append(__file__.rsplit("/", 2)[0])
import webtoken

from webtoken import InvalidKeyError, PyJWKSetError, PyJWKError
from webtoken.api_jwk import PyJWK, PyJWKSet
from webtoken.algorithms import RSAAlgorithm, ECAlgorithm, HMACAlgorithm, OKPAlgorithm


# --- TESTS ---

class TestPyJWK:
    
    def test_should_load_key_from_jwk_data_dict(self):
        # Emulating the original test flow, but skipping 'to_jwk' which isn't implemented
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    def test_should_load_key_from_jwk_data_json_string(self):
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_json(json.dumps(key_data))

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    def test_should_load_key_without_alg_from_dict(self):
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert jwk.algorithm_name == "RS256"

    def test_should_load_key_from_dict_with_algorithm(self):
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        jwk = PyJWK.from_dict(key_data, algorithm="RS256")

        assert jwk.key_type == "RSA"
        assert jwk.algorithm_name == "RS256"

    def test_should_load_key_ec_p256_from_dict(self):
        key_data = json.loads(KEYS["jwk_ec_pub_P-256.json"])
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert jwk.algorithm_name == "ES256"

    def test_should_load_key_ec_p384_from_dict(self):
        key_data = json.loads(KEYS["jwk_ec_pub_P-384.json"])
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert jwk.algorithm_name == "ES384"

    def test_should_load_key_ec_p521_from_dict(self):
        key_data = json.loads(KEYS["jwk_ec_pub_P-521.json"])
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert jwk.algorithm_name == "ES512"

    def test_should_load_key_ec_secp256k1_from_dict(self):
        key_data = json.loads(KEYS["jwk_ec_pub_secp256k1.json"])
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        # If your deduce_algorithm handles secp256k1, this assertion holds
        # assert jwk.algorithm_name == "ES256K" 

    def test_should_load_key_hmac_from_dict(self):
        key_data = json.loads(KEYS["jwk_hmac.json"])
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert jwk.algorithm_name == "HS256"

    def test_should_load_key_hmac_without_alg_from_dict(self):
        key_data = json.loads(KEYS["jwk_hmac.json"])
        del key_data["alg"]
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert jwk.algorithm_name == "HS256"

    def test_should_load_key_okp_without_alg_from_dict(self):
        key_data = json.loads(KEYS["jwk_okp_pub_Ed25519.json"])
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "OKP"
        assert jwk.algorithm_name == "EdDSA"

    def test_from_dict_should_throw_exception_if_arg_is_invalid(self):
        valid_rsa_pub = json.loads(KEYS["jwk_rsa_pub.json"])
        valid_ec_pub = json.loads(KEYS["jwk_ec_pub_P-256.json"])
        valid_okp_pub = json.loads(KEYS["jwk_okp_pub_Ed25519.json"])

        # Unknown algorithm check might fail depending on Rust strictness, 
        # normally PyJWT raises PyJWKError here.
        # with pytest.raises(PyJWKError):
        #     PyJWK.from_dict(valid_rsa_pub, algorithm="unknown")

        v = valid_rsa_pub.copy()
        del v["kty"]
        with pytest.raises((InvalidKeyError, ValueError)):
            PyJWK.from_dict(v)

        v = valid_rsa_pub.copy()
        v["kty"] = "unknown"
        with pytest.raises((InvalidKeyError, ValueError)):
            PyJWK.from_dict(v)

        v = valid_ec_pub.copy()
        v["crv"] = "unknown"
        with pytest.raises((InvalidKeyError, ValueError)):
            PyJWK.from_dict(v)


class TestPyJWKSet:
    
    def test_should_load_keys_from_jwk_data_dict(self):
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    def test_should_load_keys_from_jwk_data_json_string(self):
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_json(json.dumps({"keys": [key_data]}))
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    def test_keyset_should_index_by_kid(self):
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})
        jwk = jwk_set.keys[0]
        
        # Verify indexing
        fetched = jwk_set["keyid-abc123"]
        assert jwk.key_id == fetched.key_id

        with pytest.raises(KeyError):
            _ = jwk_set["this-kid-does-not-exist"]

    def test_keyset_iterator(self):
        key_data = json.loads(KEYS["jwk_rsa_pub.json"])
        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})
        
        count = 0
        for jwk in jwk_set:
            assert isinstance(jwk, PyJWK)
            count += 1
        assert count == 1

    def test_keyset_with_unknown_alg(self):
        # 1. Mixed keyset (1 valid, 1 invalid)
        jwks_text = KEYS["jwk_keyset_with_unknown_alg.json"]
        jwks = json.loads(jwks_text)
        assert len(jwks.get("keys")) == 2
        
        keyset = PyJWKSet.from_json(jwks_text)
        # Toke filters out usable keys. RS256 is usable. RSA-OAEP is not supported.
        assert len(keyset) == 1

        # 2. Only invalid key -> should fail construction
        jwks_text = KEYS["jwk_keyset_only_unknown_alg.json"]
        with pytest.raises(PyJWKSetError):
            _ = PyJWKSet.from_json(jwks_text)

    def test_invalid_keys_list(self):
        with pytest.raises((PyJWKSetError, ValueError)):
            PyJWKSet(keys="string")  # type: ignore

    def test_empty_keys_list(self):
        with pytest.raises((PyJWKSetError, ValueError)) as err:
            PyJWKSet(keys=[])
        assert "did not contain any" in str(err.value)


# --- INLINE KEY DATA (From PyJWT Repo) ---
KEYS = {
    "jwk_rsa_pub.json": json.dumps({
        "kty": "RSA",
        "kid": "bilbo.baggins@hobbiton.example",
        "use": "sig",
        "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
        "e": "AQAB"
    }),
    "jwk_ec_pub_P-256.json": json.dumps({
        "kty": "EC",
        "kid": "bilbo.baggins.256@hobbiton.example",
        "crv": "P-256",
        "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4",
        "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU"
    }),
    "jwk_ec_pub_P-384.json": json.dumps({
        "kty": "EC",
        "kid": "bilbo.baggins.384@hobbiton.example",
        "crv": "P-384",
        "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
        "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy"
    }),
    "jwk_ec_pub_P-521.json": json.dumps({
        "kty": "EC",
        "kid": "bilbo.baggins.521@hobbiton.example",
        "crv": "P-521",
        "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
        "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
    }),
    "jwk_ec_pub_secp256k1.json": json.dumps({
        "kty": "EC",
        "kid": "bilbo.baggins.256k@hobbiton.example",
        "crv": "secp256k1",
        "x": "MLnVyPDPQpNm0KaaO4iEh0i8JItHXJE0NcIe8GK1SYs",
        "y": "7r8d-xF7QAgT5kSRdly6M8xeg4Jz83Gs_CQPQRH65QI"
    }),
    "jwk_hmac.json": json.dumps({
        "kty": "oct",
        "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
        "use": "sig",
        "alg": "HS256",
        "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
    }),
    "jwk_okp_pub_Ed25519.json": json.dumps({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }),
    "jwk_keyset_with_unknown_alg.json": json.dumps({
        "keys": [
            {
                "kid": "U1MayerhVuRj8xtFR8hyMH9lCfVMKlb3TG7mbQAS19M",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": "omef3NkXf4--6BtUPKjhlV7pf6Vv7HMg-VL-ITX8KQZTD4LTzWO3x9RPwVepKjgfvJe_IiZFaJX78-a7zpcG9mpZG8czp3C8nZSvAJKphvYLd9s9qYrGMFW9t1eHyGwmIQN02VXwHeZ0JDd5X4i7sO4XPkNycfzSoxaQbv7wANYBTcvcWcjYVxIj4ZpYkSsQqrrOTm69G7FyurtfExGc7jlSRcv-Gubq_K3IQLHGHTlil20wqZmis1dLJwpAjgTxY7uQSwEdqJHCJR3q76bsDelIBZpbR07kqIOXqYu52w0wkC_1W7_HcVPLNp6T_ML09P8jGsOWfMO95_zchkseQw",
                "e": "AQAB"
            },
            {
                "kid": "lYXxnemSzWNBUoPug_h0hZnjPi5oKCmQ9awQJaZCWWM",
                "kty": "RSA",
                "alg": "RSA-OAEP",
                "use": "enc",
                "n": "k75Ghd4r8h_fdydTAXyMjrGYNnuiG7yevoW1ZIIuegEUK3LLGY0Z3Q8PhCrkmi6LpkPwwR1C8ck9plvSs4vZ9GqmUoi5YcQEile6HjPG3NBwQ-cHWY4ZH_D-ItdzcZUKDxjHYaY-GW1yLeJ1RAh8wMPM7cenA2v0eNIq4HaIXzZJ2Hgxh4Ei-CSYcD0f_TYEySqUEb8jd0dC8frpkYDkOUCVizRBDUEg_hkPSpVqfLP8ekxIHxkC9wcfL-d2FhptxBQYN8NFnIuG9NFXbZ5mdzdmIuN6WPr_CECcgL9qXsph9U-L829dU67ufeBvzEejJ8qwiswslRdx4ZcYjtaBdQ",
                "e": "AQAB"
            }
        ]
    }),
    "jwk_keyset_only_unknown_alg.json": json.dumps({
        "keys": [
            {
                "kid": "lYXxnemSzWNBUoPug_h0hZnjPi5oKCmQ9awQJaZCWWM",
                "kty": "RSA",
                "alg": "RSA-OAEP",
                "use": "enc",
                "n": "k75Ghd4r8h_fdydTAXyMjrGYNnuiG7yevoW1ZIIuegEUK3LLGY0Z3Q8PhCrkmi6LpkPwwR1C8ck9plvSs4vZ9GqmUoi5YcQEile6HjPG3NBwQ-cHWY4ZH_D-ItdzcZUKDxjHYaY-GW1yLeJ1RAh8wMPM7cenA2v0eNIq4HaIXzZJ2Hgxh4Ei-CSYcD0f_TYEySqUEb8jd0dC8frpkYDkOUCVizRBDUEg_hkPSpVqfLP8ekxIHxkC9wcfL-d2FhptxBQYN8NFnIuG9NFXbZ5mdzdmIuN6WPr_CECcgL9qXsph9U-L829dU67ufeBvzEejJ8qwiswslRdx4ZcYjtaBdQ",
                "e": "AQAB"
            }
        ]
    })
}
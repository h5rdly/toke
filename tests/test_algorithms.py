import base64, json, sys, warnings
from typing import Any, cast

sys.path.append(__file__.rsplit("/", 2)[0])

import webtoken as jwt
from webtoken import base64url_decode, generate_key_pair, InvalidKeyError
from webtoken.algorithms import HMACAlgorithm, NoneAlgorithm, ECAlgorithm, OKPAlgorithm, RSAAlgorithm, RSAPSSAlgorithm
from webtoken.curves import SECP256K1, SECP256R1, SECP384R1, SECP521R1

import pytest


# --Dummy Types for casts 
# PyJWT tests use these cryptography types for type checking, mocking them to avoid NameError
class RSAPublicKey: pass
class RSAPrivateKey: pass
class EllipticCurvePublicKey: pass
class EllipticCurvePrivateKey: pass
class Ed25519PrivateKey: pass
class Ed25519PublicKey: pass
class Ed448PrivateKey: pass
class Ed448PublicKey: pass


# -- Helpers to load keys 
def load_hmac_key():
    keyobj = json.loads(JWK_HMAC_KEY)
    return base64url_decode(keyobj["k"])

def load_rsa_pub_key():
    return RSAAlgorithm(RSAAlgorithm.SHA256).from_jwk(JWK_RSA_PUB_KEY)

def load_ec_pub_key_p_521():
    # webtoken's ECAlgorithm.from_jwk should handle this
    return ECAlgorithm(ECAlgorithm.SHA512).from_jwk(JWK_EC_PUB_P521)


class TestAlgorithms:

    def test_check_crypto_key_type_should_fail_when_not_using_crypto(self):
        """If has_crypto is False, or if _crypto_key_types is None, then this method should throw."""

        algo = NoneAlgorithm()
        with pytest.raises(ValueError):
            algo.check_crypto_key_type("key")  # type: ignore[arg-type]

    def test_none_algorithm_should_throw_exception_if_key_is_not_none(self):
        algo = NoneAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key("123")

    def test_none_algorithm_should_throw_exception_on_to_jwk(self):
        algo = NoneAlgorithm()

        with pytest.raises(NotImplementedError):
            algo.to_jwk("dummy")  # Using a dummy argument as is it not relevant

    def test_none_algorithm_should_throw_exception_on_from_jwk(self):
        algo = NoneAlgorithm()

        with pytest.raises(NotImplementedError):
            algo.from_jwk({})  # Using a dummy argument as is it not relevant

    def test_hmac_should_reject_nonstring_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        with pytest.raises(TypeError) as context:
            algo.prepare_key(object())  # type: ignore[arg-type]

        exception = context.value
        assert str(exception) == "Expected a string value"

    def test_hmac_should_accept_unicode_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        algo.prepare_key("awesome")


    def test_hmac_should_throw_exception(self):

        keys = TESTKEY2_RSA_PUB_PEM_KEY, TESTKEY_PKCS1_PUB_PEM, TESTKEY_RSA_CER, TESTKEY_RSA_PUB_KEY
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)

        for key in keys:
            with pytest.raises(InvalidKeyError):
                algo.prepare_key(key)


    def test_hmac_jwk_should_parse_and_verify(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.from_jwk(JWK_HMAC_KEY)

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key, signature)


    @pytest.mark.parametrize("as_dict", (False, True))
    def test_hmac_to_jwk_returns_correct_values(self, as_dict):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key: Any = algo.to_jwk("secret", as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        assert key == {"kty": "oct", "k": "c2VjcmV0"}


    def test_hmac_from_jwk_should_raise_exception_if_not_hmac_key(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(JWK_RSA_PUB_KEY)


    def test_hmac_from_jwk_should_raise_exception_if_empty_json(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(JWK_EMPTY_KEY)

    
    def test_rsa_should_parse_pem_public_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        algo.prepare_key(TESTKEY2_RSA_PUB_PEM_KEY)

    
    def test_rsa_should_accept_pem_private_key_bytes(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        algo.prepare_key(TESTKEY_RSA_PRIV_KEY)

    
    def test_rsa_should_accept_unicode_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        algo.prepare_key(TESTKEY_RSA_PRIV_KEY)

    
    def test_rsa_should_reject_non_string_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)  # type: ignore[arg-type]

    
    def test_rsa_verify_should_return_false_if_signature_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        message = b"Hello World!"

        sig = base64.b64decode(
            b"yS6zk9DBkuGTtcBzLUzSpo9gGJxJFOGvUqN01iLhWHrzBQ9ZEz3+Ae38AXp"
            b"10RWwscp42ySC85Z6zoN67yGkLNWnfmCZSEv+xqELGEvBJvciOKsrhiObUl"
            b"2mveSc1oeO/2ujkGDkkkJ2epn0YliacVjZF5+/uDmImUfAAj8lzjnHlzYix"
            b"sn5jGz1H07jYYbi9diixN8IUhXeTafwFg02IcONhum29V40Wu6O5tAKWlJX"
            b"fHJnNUzAEUOXS0WahHVb57D30pcgIji9z923q90p5c7E2cU8V+E1qe8NdCA"
            b"APCDzZZ9zQ/dgcMVaBrGrgimrcLbPjueOKFgSO+SSjIElKA=="
        )

        sig += b"123"  # Signature is now invalid
        pub_key = cast(RSAPublicKey, algo.prepare_key(TESTKEY_RSA_PUB_KEY))

        result = algo.verify(message, pub_key, sig)
        assert not result

    
    def test_ec_jwk_public_and_private_keys_should_parse_and_verify(self):

        hashes =         ECAlgorithm.SHA256, ECAlgorithm.SHA384, ECAlgorithm.SHA512, ECAlgorithm.SHA256
        curve_keys =     JWK_EC_KEY_P256,    JWK_EC_KEY_P384,    JWK_EC_KEY_P521,    JWK_EC_KEY_SECP256K1
        curve_pub_keys = JWK_EC_PUB_P256,    JWK_EC_PUB_P384,    JWK_EC_PUB_P521,    JWK_EC_PUB_SECP256K1

        for idx, hash in enumerate(hashes):
            algo = ECAlgorithm(hash)
            pub_key = cast(EllipticCurvePublicKey, algo.from_jwk(curve_pub_keys[idx]))
            priv_key = cast(EllipticCurvePrivateKey, algo.from_jwk(curve_keys[idx]))
            signature = algo.sign(b"Hello World!", priv_key)
            print(f'testing for {hash}, got {algo.verify(b"Hello World!", pub_key, signature)=}')
            assert algo.verify(b"Hello World!", pub_key, signature)

    
    def test_ec_jwk_fails_on_invalid_json(self):
        algo = ECAlgorithm(ECAlgorithm.SHA512)

        valid_points = {
            "P-256": {
                "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4",
                "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU",
            },
            "P-384": {
                "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
                "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy",
            },
            "P-521": {
                "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
                "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
            },
            "secp256k1": {
                "x": "MLnVyPDPQpNm0KaaO4iEh0i8JItHXJE0NcIe8GK1SYs",
                "y": "7r8d-xF7QAgT5kSRdly6M8xeg4Jz83Gs_CQPQRH65QI",
            },
        }

        # Invalid JSON
        with pytest.raises(InvalidKeyError):
            algo.from_jwk("<this isn't json>")

        # Bad key type
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "RSA"}')

        # Missing data
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC"}')
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC", "x": "1"}')
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC", "y": "1"}')

        # Missing curve
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC", "x": "dGVzdA==", "y": "dGVzdA=="}')

        # EC coordinates not equally long
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "EC", "x": "dGVzdHRlc3Q=", "y": "dGVzdA=="}')

        # EC coordinates length invalid
        for curve in ("P-256", "P-384", "P-521", "secp256k1"):
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(
                    f'{{"kty": "EC", "crv": "{curve}", "x": "dGVzdA==", "y": "dGVzdA=="}}'
                )

        # EC private key length invalid
        for curve, point in valid_points.items():
            with pytest.raises(InvalidKeyError):
                algo.from_jwk(
                    f'{{"kty": "EC", "crv": "{curve}", "x": "{point["x"]}", "y": "{point["y"]}", "d": "dGVzdA=="}}'
                )

    
    def test_ec_private_key_to_jwk_works_with_from_jwk(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)
        orig_key = cast(EllipticCurvePrivateKey, algo.prepare_key(TESTKEY_EC_PRIV_KEY))

        parsed_key = cast(EllipticCurvePrivateKey, algo.from_jwk(algo.to_jwk(orig_key)))
        assert parsed_key.private_numbers() == orig_key.private_numbers()
        assert (
            parsed_key.private_numbers().public_numbers
            == orig_key.private_numbers().public_numbers
        )

    
    def test_ec_public_key_to_jwk_works_with_from_jwk(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)
        orig_key = cast(EllipticCurvePublicKey, algo.prepare_key(TESTKEY_EC_PUB_KEY))

        parsed_key = cast(EllipticCurvePublicKey, algo.from_jwk(algo.to_jwk(orig_key)))
        assert parsed_key.public_numbers() == orig_key.public_numbers()

    
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_ec_to_jwk_returns_correct_values_for_public_key(self, as_dict):
        algo = ECAlgorithm(ECAlgorithm.SHA256)
        pub_key = algo.prepare_key(TESTKEY_EC_PUB_KEY)

        key: Any = algo.to_jwk(pub_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        expected = {
            "kty": "EC",
            "crv": "P-256",
            "x": "HzAcUWSlGBHcuf3y3RiNrWI-pE6-dD2T7fIzg9t6wEc",
            "y": "t2G02kbWiOqimYfQAfnARdp2CTycsJPhwA8rn1Cn0SQ",
        }

        assert key == expected

    
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_ec_to_jwk_returns_correct_values_for_private_key(self, as_dict):
        algo = ECAlgorithm(ECAlgorithm.SHA256)
        priv_key = algo.prepare_key(TESTKEY_EC_PRIV_KEY)

        key: Any = algo.to_jwk(priv_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        expected = {
            "kty": "EC",
            "crv": "P-256",
            "x": "HzAcUWSlGBHcuf3y3RiNrWI-pE6-dD2T7fIzg9t6wEc",
            "y": "t2G02kbWiOqimYfQAfnARdp2CTycsJPhwA8rn1Cn0SQ",
            "d": "2nninfu2jMHDwAbn9oERUhRADS6duQaJEadybLaa0YQ",
        }

        assert key == expected

    
    def test_ec_to_jwk_raises_exception_on_invalid_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({"not": "a valid key"})  # type: ignore[call-overload]

    

    @pytest.mark.parametrize("as_dict", (False, True))
    def test_ec_to_jwk_with_valid_curves(self, as_dict):

        curve_names =    'P-256',            'P-384',            'P-521',           'secp256k1'
        hashes =         ECAlgorithm.SHA256, ECAlgorithm.SHA384, ECAlgorithm.SHA512, ECAlgorithm.SHA256
        curve_keys =     JWK_EC_KEY_P256,    JWK_EC_KEY_P384,    JWK_EC_KEY_P521,    JWK_EC_KEY_SECP256K1
        curve_pub_keys = JWK_EC_PUB_P256,    JWK_EC_PUB_P384,    JWK_EC_PUB_P521,    JWK_EC_PUB_SECP256K1

        for idx, hash in enumerate(hashes):
            algo = ECAlgorithm(hash)

            pub_key = algo.from_jwk(curve_pub_keys[idx])
            jwk = algo.to_jwk(pub_key, as_dict=as_dict)
            if not as_dict:
                jwk = json.loads(jwk)
            assert jwk["crv"] == curve_names[idx]

            priv_key = algo.from_jwk(curve_keys[idx])
            jwk = algo.to_jwk(priv_key, as_dict=as_dict)
            if not as_dict:
                jwk = json.loads(jwk)
            assert jwk["crv"] == curve_names[idx]

    
    def test_ec_to_jwk_with_invalid_curve(self):

        algo = ECAlgorithm(ECAlgorithm.SHA256)
        priv_key = algo.prepare_key(TESTKEY_EC_SECP192R1_PRIV_KEY)
        with pytest.raises(InvalidKeyError):
            algo.to_jwk(priv_key)

    
    def test_rsa_jwk_public_and_private_keys_should_parse_and_verify(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        pub_key = cast(RSAPublicKey, algo.from_jwk(JWK_RSA_PUB_KEY))
        priv_key = cast(RSAPrivateKey, algo.from_jwk(JWK_RSA_KEY))

        signature = algo.sign(b"Hello World!", priv_key)
        assert algo.verify(b"Hello World!", pub_key, signature)

    
    def test_rsa_private_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        orig_key = cast(RSAPrivateKey, algo.prepare_key(TESTKEY_RSA_PRIV_KEY))

        parsed_key = cast(RSAPrivateKey, algo.from_jwk(algo.to_jwk(orig_key)))
        assert parsed_key.private_numbers() == orig_key.private_numbers()
        assert (
            parsed_key.private_numbers().public_numbers
            == orig_key.private_numbers().public_numbers
        )

    
    def test_rsa_public_key_to_jwk_works_with_from_jwk(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        orig_key = cast(RSAPublicKey, algo.prepare_key(TESTKEY_RSA_PUB_KEY))

        parsed_key = cast(RSAPublicKey, algo.from_jwk(algo.to_jwk(orig_key)))
        assert parsed_key.public_numbers() == orig_key.public_numbers()

    
    def test_rsa_jwk_private_key_with_other_primes_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            keydata = json.loads(JWK_RSA_KEY)
            keydata["oth"] = []

            algo.from_jwk(json.dumps(keydata))

    
    def test_rsa_jwk_private_key_with_missing_values_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            keydata = json.loads(JWK_RSA_KEY)
            del keydata["p"]

            algo.from_jwk(json.dumps(keydata))

    
    def test_rsa_jwk_private_key_can_recover_prime_factors(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        keybytes = JWK_RSA_KEY
        control_key = cast(RSAPrivateKey, algo.from_jwk(keybytes)).private_numbers()

        keydata = json.loads(keybytes)
        delete_these = ["p", "q", "dp", "dq", "qi"]
        for field in delete_these:
            del keydata[field]

        parsed_key = cast(
            RSAPrivateKey, algo.from_jwk(json.dumps(keydata))
        ).private_numbers()

        assert control_key.d == parsed_key.d
        assert control_key.p == parsed_key.p
        assert control_key.q == parsed_key.q
        assert control_key.dmp1 == parsed_key.dmp1
        assert control_key.dmq1 == parsed_key.dmq1
        assert control_key.iqmp == parsed_key.iqmp

    
    def test_rsa_jwk_private_key_with_missing_required_values_is_invalid(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            keydata = json.loads(JWK_RSA_KEY)
            del keydata["p"]

            algo.from_jwk(json.dumps(keydata))

    
    def test_rsa_jwk_raises_exception_if_not_a_valid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        # Invalid JSON
        try:
            algo.from_jwk("{not-a-real-key")
        except Exception as e:
            print(f'{str(e)=} {type(e)=}')
        with pytest.raises(InvalidKeyError):
            algo.from_jwk("{not-a-real-key")

        # Missing key parts
        with pytest.raises(InvalidKeyError):
            algo.from_jwk('{"kty": "RSA"}')

    
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_rsa_to_jwk_returns_correct_values_for_public_key(self, as_dict):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        pub_key = algo.prepare_key(TESTKEY_RSA_PUB_KEY)

        key: Any = algo.to_jwk(pub_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        expected = {
            "e": "AQAB",
            "key_ops": ["verify"],
            "kty": "RSA",
            "n": (
                "1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJdCvuCJRr-xCN-"
                "OmO8qwgJJR98feNujxVg-J9Ls3_UOA4HcF9nYH6aqVXELAE8Hk_ALvxi96ms"
                "1DDuAvQGaYZ-lANxlvxeQFOZSbjkz_9mh8aLeGKwqJLp3p-OhUBQpwvAUAPg"
                "82-OUtgTW3nSljjeFr14B8qAneGSc_wl0ni--1SRZUXFSovzcqQOkla3W27r"
                "rLfrD6LXgj_TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O_Wecwz2Nl19pL7gDo"
                "sNruF3ogJWNq1Lyn_ijPQnkPLpZHyhvuiycYcI3DiQ"
            ),
        }
        print (f'{type(key)=} {type(expected)=}')
        assert key == expected

    
    @pytest.mark.parametrize("as_dict", (False, True))
    def test_rsa_to_jwk_returns_correct_values_for_private_key(self, as_dict):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        priv_key = algo.prepare_key(TESTKEY_RSA_PRIV_KEY)

        key: Any = algo.to_jwk(priv_key, as_dict=as_dict)

        if not as_dict:
            key = json.loads(key)

        expected = {
            "key_ops": ["sign"],
            "kty": "RSA",
            "e": "AQAB",
            "n": (
                "1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJdCvuCJRr-xCN-"
                "OmO8qwgJJR98feNujxVg-J9Ls3_UOA4HcF9nYH6aqVXELAE8Hk_ALvxi96ms"
                "1DDuAvQGaYZ-lANxlvxeQFOZSbjkz_9mh8aLeGKwqJLp3p-OhUBQpwvAUAPg"
                "82-OUtgTW3nSljjeFr14B8qAneGSc_wl0ni--1SRZUXFSovzcqQOkla3W27r"
                "rLfrD6LXgj_TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O_Wecwz2Nl19pL7gDo"
                "sNruF3ogJWNq1Lyn_ijPQnkPLpZHyhvuiycYcI3DiQ"
            ),
            "d": (
                "rfbs8AWdB1RkLJRlC51LukrAvYl5UfU1TE6XRa4o-DTg2-03OXLNEMyVpMr"
                "a47weEnu14StypzC8qXL7vxXOyd30SSFTffLfleaTg-qxgMZSDw-Fb_M-pU"
                "HMPMEDYG-lgGma4l4fd1yTX2ATtoUo9BVOQgWS1LMZqi0ASEOkUfzlBgL04"
                "UoaLhPSuDdLygdlDzgruVPnec0t1uOEObmrcWIkhwU2CGQzeLtuzX6OVgPh"
                "k7xcnjbDurTTVpWH0R0gbZ5ukmQ2P-YuCX8T9iWNMGjPNSkb7h02s2Oe9ZR"
                "zP007xQ0VF-Z7xyLuxk6ASmoX1S39ujSbk2WF0eXNPRgFwQ"
            ),
            "q": (
                "47hlW2f1ARuWYJf9Dl6MieXjdj2dGx9PL2UH0unVzJYInd56nqXNPrQrc5k"
                "ZU65KApC9n9oKUwIxuqwAAbh8oGNEQDqnuTj-powCkdC6bwA8KH1Y-wotpq"
                "_GSjxkNzjWRm2GArJSzZc6Fb8EuObOrAavKJ285-zMPCEfus1WZG0"
            ),
            "p": (
                "7tr0z929Lp4OHIRJjIKM_rDrWMPtRgnV-51pgWsN6qdpDzns_PgFwrHcoyY"
                "sWIO-4yCdVWPxFOgEZ8xXTM_uwOe4VEmdZhw55Tx7axYZtmZYZbO_RIP4CG"
                "mlJlOFTiYnxpr-2Cx6kIeQmd-hf7fA3tL018aEzwYMbFMcnAGnEg0"
            ),
            "qi": (
                "djo95mB0LVYikNPa-NgyDwLotLqrueb9IviMmn6zKHCwiOXReqXDX9slB8"
                "RA15uv56bmN04O__NyVFcgJ2ef169GZHiRFIgIy0Pl8LYkMhCYKKhyqM7g"
                "xN-SqGqDTKDC22j00S7jcvCaa1qadn1qbdfukZ4NXv7E2d_LO0Y2Kkc"
            ),
            "dp": (
                "tgZ2-tJpEdWxu1m1EzeKa644LHVjpTRptk7H0LDc8i6SieADEuWQvkb9df"
                "fpY6tDFaQNQr3fQ6dtdAztmsP7l1b_ynwvT1nDZUcqZvl4ruBgDWFmKbjI"
                "lOCt0v9jX6MEPP5xqBx9axdkw18BnGtUuHrbzHSlUX-yh_rumpVH1SE"
            ),
            "dq": (
                "xxCIuhD0YlWFbUcwFgGdBWcLIm_WCMGj7SB6aGu1VDTLr4Wu10TFWM0TNu"
                "hc9YPker2gpj5qzAmdAzwcfWSSvXpJTYR43jfulBTMoj8-2o3wCM0anclW"
                "AuKhin-kc4mh9ssDXRQZwlMymZP0QtaxUDw_nlfVrUCZgO7L1_ZsUTk"
            ),
        }
        assert key == expected

    
    def test_rsa_to_jwk_raises_exception_on_invalid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({"not": "a valid key"})  # type: ignore[call-overload]

    
    def test_rsa_from_jwk_raises_exception_on_invalid_key(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(JWK_HMAC_KEY)

    
    def test_ec_should_reject_non_string_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(TypeError):
            algo.prepare_key(None)  # type: ignore[arg-type]

    
    def test_ec_should_accept_pem_private_key_bytes(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)
        algo.prepare_key(TESTKEY_EC_PRIV_KEY)

    
    def test_ec_should_accept_ssh_public_key_bytes(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        algo.prepare_key(TESTKEY_EC_SSH_PUB_KEY)

    
    def test_ec_verify_should_return_false_if_signature_invalid(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = b"Hello World!"

        # Mess up the signature by replacing a known byte
        sig = base64.b64decode(
            b"AC+m4Jf/xI3guAC6w0w37t5zRpSCF6F4udEz5LiMiTIjCS4vcVe6dDOxK+M"
            b"mvkF8PxJuvqxP2CO3TR3okDPCl/NjATTO1jE+qBZ966CRQSSzcCM+tzcHzw"
            b"LZS5kbvKu0Acd/K6Ol2/W3B1NeV5F/gjvZn/jOwaLgWEUYsg0o4XVrAg65".replace(
                b"r", b"s"
            )
        )
        pub_key = algo.prepare_key(TESTKEY_EC_PUB_KEY)

        result = algo.verify(message, pub_key, sig)
        assert not result

    
    def test_ec_verify_should_return_false_if_signature_wrong_length(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        message = b"Hello World!"

        sig = base64.b64decode(b"AC+m4Jf/xI3guAC6w0w3")
        pub_key = algo.prepare_key(TESTKEY_EC_PUB_KEY)

        result = algo.verify(message, pub_key, sig)
        assert not result

    
    def test_ec_should_throw_exception_on_wrong_key(self):
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        with pytest.raises(InvalidKeyError):
            algo.prepare_key(TESTKEY_RSA_PRIV_KEY)

        with pytest.raises(InvalidKeyError):
            algo.prepare_key(TESTKEY2_RSA_PUB_PEM_KEY)

    
    def test_rsa_pss_sign_then_verify_should_return_true(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        message = b"Hello World!"
        priv_key = cast(RSAPrivateKey, algo.prepare_key(TESTKEY_RSA_PRIV_KEY))
        sig = algo.sign(message, priv_key)
        pub_key = cast(RSAPublicKey, algo.prepare_key(TESTKEY_RSA_PUB_KEY))

        result = algo.verify(message, pub_key, sig)
        assert result

    
    def test_rsa_pss_verify_should_return_false_if_signature_invalid(self):
        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)

        jwt_message = b"Hello World!"

        jwt_sig = base64.b64decode(
            b"ywKAUGRIDC//6X+tjvZA96yEtMqpOrSppCNfYI7NKyon3P7doud5v65oWNu"
            b"vQsz0fzPGfF7mQFGo9Cm9Vn0nljm4G6PtqZRbz5fXNQBH9k10gq34AtM02c"
            b"/cveqACQ8gF3zxWh6qr9jVqIpeMEaEBIkvqG954E0HT9s9ybHShgHX9mlWk"
            b"186/LopP4xe5c/hxOQjwhv6yDlTiwJFiqjNCvj0GyBKsc4iECLGIIO+4mC4"
            b"daOCWqbpZDuLb1imKpmm8Nsm56kAxijMLZnpCcnPgyb7CqG+B93W9GHglA5"
            b"drUeR1gRtO7vqbZMsCAQ4bpjXxwbYyjQlEVuMl73UL6sOWg=="
        )

        jwt_sig += b"123"  # Signature is now invalid
        jwt_pub_key = cast(RSAPublicKey, algo.prepare_key(TESTKEY_RSA_PUB_KEY))

        result = algo.verify(jwt_message, jwt_pub_key, jwt_sig)
        assert not result


class TestAlgorithmsRFC7520:
    """
    These test vectors were taken from RFC 7520
    (https://tools.ietf.org/html/rfc7520)
    """

    def test_hmac_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that HMAC verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.4
        """
        signing_input = (
            b"eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZ"
            b"jMxNGJjNzAzNyJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ"
            b"29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIG"
            b"lmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmc"
            b"gd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(b"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0")

        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(load_hmac_key())

        result = algo.verify(signing_input, key, signature)
        assert result

    
    def test_rsa_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that RSA PKCS v1.5 verification works with a known
        good signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.1
        """
        signing_input = (
            b"eyJhbGciOiJSUzI1NiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb"
            b"XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb"
            b"3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS"
            b"Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU"
            b"geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(
            b"MRjdkly7_-oTPTS3AXP41iQIGKa80A0ZmTuV5MEaHoxnW2e5CZ5NlKtainoFmKZop"
            b"dHM1O2U4mwzJdQx996ivp83xuglII7PNDi84wnB-BDkoBwA78185hX-Es4JIwmDLJ"
            b"K3lfWRa-XtL0RnltuYv746iYTh_qHRD68BNt1uSNCrUCTJDt5aAE6x8wW1Kt9eRo4"
            b"QPocSadnHXFxnt8Is9UzpERV0ePPQdLuW3IS_de3xyIrDaLGdjluPxUAhb6L2aXic"
            b"1U12podGU0KLUQSE_oI-ZnmKJ3F4uOZDnd6QZWJushZ41Axf_fcIe8u9ipH84ogor"
            b"ee7vjbU5y18kDquDg"
        )

        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        key = cast(RSAPublicKey, algo.prepare_key(load_rsa_pub_key()))

        result = algo.verify(signing_input, key, signature)
        assert result

    
    def test_rsapss_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that RSA-PSS verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.2
        """
        signing_input = (
            b"eyJhbGciOiJQUzM4NCIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb"
            b"XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb"
            b"3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS"
            b"Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU"
            b"geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(
            b"cu22eBqkYDKgIlTpzDXGvaFfz6WGoz7fUDcfT0kkOy42miAh2qyBzk1xEsnk2IpN6"
            b"-tPid6VrklHkqsGqDqHCdP6O8TTB5dDDItllVo6_1OLPpcbUrhiUSMxbbXUvdvWXz"
            b"g-UD8biiReQFlfz28zGWVsdiNAUf8ZnyPEgVFn442ZdNqiVJRmBqrYRXe8P_ijQ7p"
            b"8Vdz0TTrxUeT3lm8d9shnr2lfJT8ImUjvAA2Xez2Mlp8cBE5awDzT0qI0n6uiP1aC"
            b"N_2_jLAeQTlqRHtfa64QQSUmFAAjVKPbByi7xho0uTOcbH510a6GYmJUAfmWjwZ6o"
            b"D4ifKo8DYM-X72Eaw"
        )

        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384)
        key = cast(RSAPublicKey, algo.prepare_key(load_rsa_pub_key()))

        result = algo.verify(signing_input, key, signature)
        assert result

    
    def test_ec_verify_should_return_true_for_test_vector(self):
        """
        This test verifies that ECDSA verification works with a known good
        signature and key.

        Reference: https://tools.ietf.org/html/rfc7520#section-4.3
        """
        signing_input = (
            b"eyJhbGciOiJFUzUxMiIsImtpZCI6ImJpbGJvLmJhZ2dpbnNAaG9iYml0b24uZXhhb"
            b"XBsZSJ9.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb"
            b"3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdS"
            b"Bkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmU"
            b"geW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
        )

        signature = base64url_decode(
            b"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvbu9P"
            b"lon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kvAD890j"
            b"l8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2"
        )

        algo = ECAlgorithm(ECAlgorithm.SHA512)
        key = algo.prepare_key(load_ec_pub_key_p_521())

        result = algo.verify(signing_input, key, signature)
        assert result

        # private key can also be used.
        private_key = algo.from_jwk(JWK_EC_KEY_P521)

        result = algo.verify(signing_input, private_key, signature)
        assert result



class TestOKPAlgorithms:

    hello_world_sig = b"Qxa47mk/azzUgmY2StAOguAd4P7YBLpyCfU3JdbaiWnXM4o4WibXwmIHvNYgN3frtE2fcyd8OYEaOiD/KiwkCg=="
    hello_world_sig_pem = b"9ueQE7PT8uudHIQb2zZZ7tB7k1X3jeTnIfOVvGCINZejrqQbru1EXPeuMlGcQEZrGkLVcfMmr99W/+byxfppAg=="
    hello_world = b"Hello World!"


    def test_okp_ed25519_should_reject_non_string_key(self):
        algo = OKPAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key(None)  # type: ignore[arg-type]

        algo.prepare_key(TESTKEY_ED25519_PRIV)

        algo.prepare_key(TESTKEY_ED25519_PUB)


    def test_okp_ed25519_sign_should_generate_correct_signature_value(self):

        algo = OKPAlgorithm()
        jwt_message = self.hello_world

        expected_sig = base64.b64decode(getattr(self, 'hello_world_sig'))
        jwt_key = cast(Ed25519PrivateKey, algo.prepare_key(TESTKEY_ED25519_PRIV))
        jwt_pub_key = cast(Ed25519PublicKey, algo.prepare_key(TESTKEY_ED25519_PUB))
        algo.sign(jwt_message, jwt_key)
        assert algo.verify(jwt_message, jwt_pub_key, expected_sig)

        expected_sig = base64.b64decode(getattr(self, 'hello_world_sig_pem'))
        jwt_key = cast(Ed25519PrivateKey, algo.prepare_key(TESTKEY_ED25519_PRIV_PEM))
        jwt_pub_key = cast(Ed25519PublicKey, algo.prepare_key(TESTKEY_ED25519_PUB_PEM))
        algo.sign(jwt_message, jwt_key)
        assert algo.verify(jwt_message, jwt_pub_key, expected_sig)


    def test_okp_ed25519_verify_should_return_false_if_signature_invalid(self):
        
        algo = OKPAlgorithm()
        jwt_message = self.hello_world

        jwt_sig = base64.b64decode(getattr(self, 'hello_world_sig'))
        jwt_sig += b"123"  # Signature is now invalid
        jwt_pub_key = algo.prepare_key(TESTKEY_ED25519_PUB)
        assert not algo.verify(jwt_message, jwt_pub_key, jwt_sig)

        jwt_sig = base64.b64decode(getattr(self, 'hello_world_sig_pem'))
        jwt_sig += b"123"  # Signature is now invalid
        jwt_pub_key = algo.prepare_key(TESTKEY_ED25519_PUB_PEM)
        assert not algo.verify(jwt_message, jwt_pub_key, jwt_sig)




    def test_okp_ed25519_verify_should_return_true_if_signature_valid(self):
        algo = OKPAlgorithm()
        jwt_message = self.hello_world

        jwt_sig = base64.b64decode(getattr(self, "hello_world_sig"))
        jwt_pub_key = algo.prepare_key(TESTKEY_ED25519_PUB)
        assert algo.verify(jwt_message, jwt_pub_key, jwt_sig)

        jwt_sig = base64.b64decode(getattr(self, "hello_world_sig_pem"))
        jwt_pub_key = algo.prepare_key(TESTKEY_ED25519_PUB_PEM)
        assert algo.verify(jwt_message, jwt_pub_key, jwt_sig)




    def test_okp_ed25519_prepare_key_should_be_idempotent(self):

        algo = OKPAlgorithm()

        jwt_pub_key_first = algo.prepare_key(TESTKEY_ED25519_PUB)
        jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)
        assert jwt_pub_key_first == jwt_pub_key_second

        jwt_pub_key_first = algo.prepare_key(TESTKEY_ED25519_PUB_PEM)
        jwt_pub_key_second = algo.prepare_key(jwt_pub_key_first)
        assert jwt_pub_key_first == jwt_pub_key_second


    def test_okp_ed25519_prepare_key_should_reject_invalid_key(self):
        algo = OKPAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.prepare_key("not a valid key")


    def test_okp_ed25519_jwk_private_key_should_parse_and_verify(self):
        algo = OKPAlgorithm()

        key = cast(Ed25519PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED25519))

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key.public_key(), signature)


    def test_okp_ed25519_jwk_private_key_should_parse_and_verify_with_private_key_as_is(
        self,
    ):
        algo = OKPAlgorithm()

        key = cast(Ed25519PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED25519))

        signature = algo.sign(b"Hello World!", key)
        assert algo.verify(b"Hello World!", key, signature)


    def test_okp_ed25519_jwk_public_key_should_parse_and_verify(self):
        algo = OKPAlgorithm()

        priv_key = cast(Ed25519PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED25519))

        pub_key = cast(Ed25519PublicKey, algo.from_jwk(JWK_OKP_PUB_ED25519))

        signature = algo.sign(b"Hello World!", priv_key)
        assert algo.verify(b"Hello World!", pub_key, signature)


    def test_okp_ed25519_jwk_fails_on_invalid_json(self):
        algo = OKPAlgorithm()

        valid_pub = json.loads(JWK_OKP_PUB_ED25519)
        valid_key = json.loads(JWK_OKP_KEY_ED25519)

        # Invalid instance type
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(123)  # type: ignore[arg-type]

        # Invalid JSON
        with pytest.raises(InvalidKeyError):
            algo.from_jwk("<this isn't json>")

        # Invalid kty, not "OKP"
        v = valid_pub.copy()
        v["kty"] = "oct"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid crv, not "Ed25519"
        v = valid_pub.copy()
        v["crv"] = "P-256"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid crv, "Ed448"
        v = valid_pub.copy()
        v["crv"] = "Ed448"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Missing x
        v = valid_pub.copy()
        del v["x"]
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid x
        v = valid_pub.copy()
        v["x"] = "123"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)

        # Invalid d
        v = valid_key.copy()
        v["d"] = "123"
        with pytest.raises(InvalidKeyError):
            algo.from_jwk(v)


    @pytest.mark.parametrize("as_dict", (False, True))
    def test_okp_ed25519_to_jwk_works_with_from_jwk(self, as_dict):
        algo = OKPAlgorithm()

        priv_key_1 = cast(Ed25519PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED25519))

        pub_key_1 = cast(Ed25519PublicKey, algo.from_jwk(JWK_OKP_PUB_ED25519))

        pub = algo.to_jwk(pub_key_1, as_dict=as_dict)
        pub_key_2 = algo.from_jwk(pub)
        pri = algo.to_jwk(priv_key_1, as_dict=as_dict)
        priv_key_2 = cast(Ed25519PrivateKey, algo.from_jwk(pri))

        signature_1 = algo.sign(b"Hello World!", priv_key_1)
        signature_2 = algo.sign(b"Hello World!", priv_key_2)
        assert algo.verify(b"Hello World!", pub_key_2, signature_1)
        assert algo.verify(b"Hello World!", pub_key_2, signature_2)


    def test_okp_to_jwk_raises_exception_on_invalid_key(self):
        algo = OKPAlgorithm()

        with pytest.raises(InvalidKeyError):
            algo.to_jwk({"not": "a valid key"})  # type: ignore[call-overload]


## ---  Webtoken does not support ED448 since aws-lc-rs doesn't

#     def test_okp_ed448_jwk_private_key_should_parse_and_verify(self):
#         algo = OKPAlgorithm()

#         key = cast(Ed448PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED448))

#         signature = algo.sign(b"Hello World!", key)
#         assert algo.verify(b"Hello World!", key.public_key(), signature)


#     def test_okp_ed448_jwk_private_key_should_parse_and_verify_with_private_key_as_is(
#         self,
#     ):
#         algo = OKPAlgorithm()

#         key = cast(Ed448PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED448))

#         signature = algo.sign(b"Hello World!", key)
#         assert algo.verify(b"Hello World!", key, signature)


#     def test_okp_ed448_jwk_public_key_should_parse_and_verify(self):
#         algo = OKPAlgorithm()

#         priv_key = cast(Ed448PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED448))

#         pub_key = cast(Ed448PublicKey, algo.from_jwk(JWK_OKP_PUB_ED448))

#         signature = algo.sign(b"Hello World!", priv_key)
#         assert algo.verify(b"Hello World!", pub_key, signature)


#     def test_okp_ed448_jwk_fails_on_invalid_json(self):
#         algo = OKPAlgorithm()

#         valid_pub = json.loads(JWK_OKP_PUB_ED448)
#         valid_key = json.loads(JWK_OKP_KEY_ED448)

#         # Invalid instance type
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk(123)  # type: ignore[arg-type]

#         # Invalid JSON
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk("<this isn't json>")

#         # Invalid kty, not "OKP"
#         v = valid_pub.copy()
#         v["kty"] = "oct"
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk(v)

#         # Invalid crv, not "Ed448"
#         v = valid_pub.copy()
#         v["crv"] = "P-256"
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk(v)

#         # Invalid crv, "Ed25519"
#         v = valid_pub.copy()
#         v["crv"] = "Ed25519"
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk(v)

#         # Missing x
#         v = valid_pub.copy()
#         del v["x"]
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk(v)

#         # Invalid x
#         v = valid_pub.copy()
#         v["x"] = "123"
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk(v)

#         # Invalid d
#         v = valid_key.copy()
#         v["d"] = "123"
#         with pytest.raises(InvalidKeyError):
#             algo.from_jwk(v)


    # @pytest.mark.parametrize("as_dict", (False, True))
    # def test_okp_ed448_to_jwk_works_with_from_jwk(self, as_dict):
    #     algo = OKPAlgorithm()

    #     priv_key_1 = cast(Ed448PrivateKey, algo.from_jwk(JWK_OKP_KEY_ED448))

    #     pub_key_1 = cast(Ed448PublicKey, algo.from_jwk(JWK_OKP_PUB_ED448))

    #     pub = algo.to_jwk(pub_key_1, as_dict=as_dict)
    #     pub_key_2 = algo.from_jwk(pub)
    #     pri = algo.to_jwk(priv_key_1, as_dict=as_dict)
    #     priv_key_2 = cast(Ed448PrivateKey, algo.from_jwk(pri))

    #     signature_1 = algo.sign(b"Hello World!", priv_key_1)
    #     signature_2 = algo.sign(b"Hello World!", priv_key_2)
    #     assert algo.verify(b"Hello World!", pub_key_2, signature_1)
    #     assert algo.verify(b"Hello World!", pub_key_2, signature_2)

    ## --- / ED448 tests

    def test_rsa_can_compute_digest(self):
        # this is the well-known sha256 hash of "foo"
        foo_hash = base64.b64decode(b"LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=")

        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        computed_hash = algo.compute_hash_digest(b"foo")
        assert computed_hash == foo_hash


    def test_hmac_can_compute_digest(self):
        # this is the well-known sha256 hash of "foo"
        foo_hash = base64.b64decode(b"LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564=")

        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        computed_hash = algo.compute_hash_digest(b"foo")
        assert computed_hash == foo_hash

    
    def test_rsa_prepare_key_raises_invalid_key_error_on_invalid_pem(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        invalid_key = "invalid key"

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(invalid_key)

        # Check that the exception message is correct
        assert "Could not parse the provided public key." in str(excinfo.value)



class TestECCurveValidation:
    """Tests for ECDSA curve validation per RFC 7518 Section 3.4."""

    def test_ec_curve_validation_rejects_wrong_curve_for_es256(self):
        """ES256 should reject keys that are not P-256."""

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        # P-384 key should be rejected
        p384_key = ECAlgorithm.from_jwk(JWK_EC_KEY_P384)

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p384_key)
        assert "secp384r1" in str(excinfo.value)
        assert "secp256r1" in str(excinfo.value)

    def test_ec_curve_validation_rejects_wrong_curve_for_es384(self):
        """ES384 should reject keys that are not P-384."""

        algo = ECAlgorithm(ECAlgorithm.SHA384, SECP384R1)

        # P-256 key should be rejected
        p256_key = ECAlgorithm.from_jwk(JWK_EC_KEY_P256)

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p256_key)
        assert "secp256r1" in str(excinfo.value)
        assert "secp384r1" in str(excinfo.value)

    def test_ec_curve_validation_rejects_wrong_curve_for_es512(self):
        """ES512 should reject keys that are not P-521."""

        algo = ECAlgorithm(ECAlgorithm.SHA512, SECP521R1)

        # P-256 key should be rejected
        p256_key = ECAlgorithm.from_jwk(JWK_EC_KEY_P256)

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p256_key)
        assert "secp256r1" in str(excinfo.value)
        assert "secp521r1" in str(excinfo.value)

    def test_ec_curve_validation_rejects_wrong_curve_for_es256k(self):
        """ES256K should reject keys that are not secp256k1."""

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256K1)

        # P-256 key should be rejected
        p256_key = ECAlgorithm.from_jwk(JWK_EC_KEY_P256)

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(p256_key)
        assert "secp256r1" in str(excinfo.value)
        assert "secp256k1" in str(excinfo.value)


    def test_ec_curve_validation_accepts_correct_curve_for_es256(self):
        """ES256 should accept P-256 keys."""

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        key = algo.from_jwk(JWK_EC_KEY_P256)
        prepared = algo.prepare_key(key)
        assert prepared is key


    def test_ec_curve_validation_accepts_correct_curve_for_es384(self):
        """ES384 should accept P-384 keys."""

        algo = ECAlgorithm(ECAlgorithm.SHA384, SECP384R1)

        key = algo.from_jwk(JWK_EC_KEY_P384)
        prepared = algo.prepare_key(key)
        assert prepared is key


    def test_ec_curve_validation_accepts_correct_curve_for_es512(self):
        """ES512 should accept P-521 keys."""

        algo = ECAlgorithm(ECAlgorithm.SHA512, SECP521R1)

        key = algo.from_jwk(JWK_EC_KEY_P521)
        prepared = algo.prepare_key(key)
        assert prepared is key

    def test_ec_curve_validation_accepts_correct_curve_for_es256k(self):
        """ES256K should accept secp256k1 keys."""

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256K1)

        key = algo.from_jwk(JWK_EC_KEY_SECP256K1)
        prepared = algo.prepare_key(key)
        assert prepared is key

    def test_ec_curve_validation_rejects_p192_for_es256(self):
        """ES256 should reject P-192 keys (weaker than P-256)."""

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        with pytest.raises(InvalidKeyError) as excinfo:
            algo.prepare_key(TESTKEY_EC_SECP192R1_PRIV_KEY)
        assert "secp192r1" in str(excinfo.value)
        assert "secp256r1" in str(excinfo.value)


    def test_ec_algorithm_without_expected_curve_accepts_any_curve(self):
        """ECAlgorithm without expected_curve should accept any curve (backwards compat)."""
        algo = ECAlgorithm(ECAlgorithm.SHA256)

        # Should accept P-256
        p256_key = algo.from_jwk(JWK_EC_KEY_P256)
        algo.prepare_key(p256_key)

        # Should accept P-384
        p384_key = algo.from_jwk(JWK_EC_KEY_P384)
        algo.prepare_key(p384_key)

        # Should accept P-521
        p521_key = algo.from_jwk(JWK_EC_KEY_P521)
        algo.prepare_key(p521_key)

        # Should accept secp256k1
        secp256k1_key = algo.from_jwk(JWK_EC_KEY_SECP256K1)
        algo.prepare_key(secp256k1_key)


    def test_default_algorithms_have_correct_expected_curve(self):
        """Default algorithms returned by get_default_algorithms should have expected_curve set."""
        from webtoken.algorithms import get_default_algorithms

        algorithms = get_default_algorithms()

        es256 = algorithms["ES256"]
        assert isinstance(es256, ECAlgorithm)
        assert es256.expected_curve == SECP256R1

        es256k = algorithms["ES256K"]
        assert isinstance(es256k, ECAlgorithm)
        assert es256k.expected_curve == SECP256K1

        es384 = algorithms["ES384"]
        assert isinstance(es384, ECAlgorithm)
        assert es384.expected_curve == SECP384R1

        es521 = algorithms["ES521"]
        assert isinstance(es521, ECAlgorithm)
        assert es521.expected_curve == SECP521R1

        es512 = algorithms["ES512"]
        assert isinstance(es512, ECAlgorithm)
        assert es512.expected_curve == SECP521R1


    def test_ec_curve_validation_with_pem_key(self):
        """Curve validation should work with PEM-formatted keys."""

        algo = ECAlgorithm(ECAlgorithm.SHA256, SECP256R1)

        # P-256 PEM key should be accepted
        algo.prepare_key(TESTKEY_EC_PRIV_KEY)

        # P-192 PEM key should be rejected
        with pytest.raises(InvalidKeyError):
            algo.prepare_key(TESTKEY_EC_SECP192R1_PRIV_KEY)


    def test_jwt_encode_decode_rejects_wrong_curve(self):
        """Integration test: jwt.encode/decode should reject wrong curve keys."""

        # Use P-384 key with ES256 algorithm (expects P-256)
        p384_key = ECAlgorithm.from_jwk(JWK_EC_KEY_P384)

        # Encoding should fail
        with pytest.raises(InvalidKeyError):
            jwt.encode({"hello": "world"}, p384_key, algorithm="ES256")

        # Create a valid token with P-256 key
        p256_key = ECAlgorithm.from_jwk(JWK_EC_KEY_P256)

        token = jwt.encode({"hello": "world"}, p256_key, algorithm="ES256")

        # Decoding with wrong curve key should fail
        p384_pub_key = ECAlgorithm.from_jwk(JWK_EC_PUB_P384)

        with pytest.raises(InvalidKeyError):
            jwt.decode(token, p384_pub_key, algorithms=["ES256"])

        # Decoding with correct curve key should succeed
        p256_pub_key = ECAlgorithm.from_jwk(JWK_EC_PUB_P256)

        decoded = jwt.decode(token, p256_pub_key, algorithms=["ES256"])
        assert decoded == {"hello": "world"}


class TestKeyLengthValidation:
    """Tests for minimum key length validation (CWE-326)."""

    # --- HMAC tests ---

    def test_hmac_short_key_warns_by_default_hs256(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(b"short")
        msg = algo.check_key_length(key)
        assert msg is not None
        assert "below" in msg
        assert "32" in msg

    def test_hmac_short_key_warns_by_default_hs384(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA384)
        key = algo.prepare_key(b"a" * 47)
        msg = algo.check_key_length(key)
        assert msg is not None
        assert "48" in msg

    def test_hmac_short_key_warns_by_default_hs512(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA512)
        key = algo.prepare_key(b"a" * 63)
        msg = algo.check_key_length(key)
        assert msg is not None
        assert "64" in msg

    def test_hmac_empty_key_returns_warning_message(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(b"")
        msg = algo.check_key_length(key)
        assert msg is not None

    def test_hmac_exact_minimum_no_warning(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA256)
        key = algo.prepare_key(b"a" * 32)
        assert algo.check_key_length(key) is None

    def test_hmac_above_minimum_no_warning(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA512)
        key = algo.prepare_key(b"a" * 128)
        assert algo.check_key_length(key) is None

    def test_hmac_exact_minimum_hs384(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA384)
        key = algo.prepare_key(b"a" * 48)
        assert algo.check_key_length(key) is None

    def test_hmac_exact_minimum_hs512(self):
        algo = HMACAlgorithm(HMACAlgorithm.SHA512)
        key = algo.prepare_key(b"a" * 64)
        assert algo.check_key_length(key) is None


    # --- RSA tests ---

    
    def test_rsa_small_key_returns_warning_message(self):

        small_key = RSA_1024_PRIVATE_KEY
        
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        msg = algo.check_key_length(small_key)
        assert msg is not None
        assert "1024" in msg
        assert "2048" in msg

    
    def test_rsa_small_public_key_returns_warning_message(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module

        small_key = rsa_module.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        msg = algo.check_key_length(small_key.public_key())
        assert msg is not None

    
    def test_rsa_2048_key_no_warning(self):
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        key = algo.prepare_key(TESTKEY_RSA_PRIV_KEY)
        assert algo.check_key_length(key) is None

    
    def test_rsa_pss_inherits_validation(self):

        small_key = RSA_1024_PRIVATE_KEY

        algo = RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256)
        msg = algo.check_key_length(small_key)
        assert msg is not None

    
    def test_rsa_pem_weak_key_validated(self):
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_module
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        small_key = rsa_module.generate_private_key(
            public_exponent=65537,
            key_size=1024,
        )
        pem = small_key.private_bytes(
            Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
        )
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        prepared = algo.prepare_key(pem)
        msg = algo.check_key_length(prepared)
        assert msg is not None


    # --- PyJWS integration tests ---

    def test_pyjws_encode_warns_short_hmac_key(self):
        jws = jwt.PyJWS()
        with pytest.warns(jwt.InsecureKeyLengthWarning, match="below"):
            jws.encode(b'{"test":"payload"}', b"short", algorithm="HS256")

    def test_pyjws_encode_enforces_short_hmac_key(self):
        jws = jwt.PyJWS(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError, match="below"):
            jws.encode(b'{"test":"payload"}', b"short", algorithm="HS256")

    def test_pyjws_encode_no_warning_adequate_key(self):
        jws = jwt.PyJWS()
        with warnings.catch_warnings():
            warnings.simplefilter("error", jwt.InsecureKeyLengthWarning)
            jws.encode(b'{"test":"payload"}', b"a" * 32, algorithm="HS256")

    # --- PyJWT integration tests ---

    # def test_pyjwt_encode_warns_short_hmac_key(self):

    #     with pytest.warns(jwt.InsecureKeyLengthWarning):
    #         jwt.encode({"hello": "world"}, "short", algorithm="HS256")


    def test_pyjwt_encode_enforces_short_hmac_key(self):

        pyjwt = jwt.PyJWT(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError, match="below"):
            pyjwt.encode({"hello": "world"}, "short", algorithm="HS256")


    def test_pyjwt_decode_enforces_short_hmac_key(self):

        adequate_key = "a" * 32
        token = jwt.encode({"hello": "world"}, adequate_key, algorithm="HS256")

        pyjwt = jwt.PyJWT(options={"enforce_minimum_key_length": True})
        # Decoding with adequate key should work
        result = pyjwt.decode(token, adequate_key, algorithms=["HS256"])
        assert result == {"hello": "world"}

        # Decoding with short key should raise
        pyjwt_enforce = jwt.PyJWT(options={"enforce_minimum_key_length": True})
        with pytest.raises(InvalidKeyError):
            pyjwt_enforce.decode(token, "short", algorithms=["HS256"])


    def test_pyjwt_encode_no_warning_adequate_key(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", jwt.InsecureKeyLengthWarning)
            jwt.encode({"hello": "world"}, "a" * 32, algorithm="HS256")

    def test_global_register_algorithm_works_with_encode(self):
        """Backward compat: jwt.register_algorithm + jwt.encode use the same JWS."""

        # This test just verifies the global path still works
        # (register_algorithm and encode share the same JWS instance)
        token = jwt.encode({"hello": "world"}, "a" * 32, algorithm="HS256")
        decoded = jwt.decode(token, "a" * 32, algorithms=["HS256"])
        assert decoded == {"hello": "world"}










# -- Keys ---

JWK_EC_KEY_P256 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.256@hobbiton.example",
  "crv": "P-256",
  "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4",
  "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU",
  "d": "9GJquUJf57a9sev-u8-PoYlIezIPqI_vGpIaiu4zyZk"
}"""

JWK_EC_KEY_P384 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.384@hobbiton.example",
  "crv": "P-384",
  "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
  "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy",
  "d": "xKPj5IXjiHpQpLOgyMGo6lg_DUp738SuXkiugCFMxbGNKTyTprYPfJz42wTOXbtd"
}"""

JWK_EC_KEY_P521 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.521@hobbiton.example",
  "crv": "P-521",
  "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
  "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1",
  "d": "AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zbKipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt"
}"""

JWK_EC_KEY_SECP256K1 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.256k@hobbiton.example",
  "crv": "secp256k1",
  "x": "MLnVyPDPQpNm0KaaO4iEh0i8JItHXJE0NcIe8GK1SYs",
  "y": "7r8d-xF7QAgT5kSRdly6M8xeg4Jz83Gs_CQPQRH65QI",
  "d": "XV7LOlEOANIaSxyil8yE8NPDT5jmVw_HQeCwNDzochQ"
}"""

JWK_EC_PUB_P256 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.256@hobbiton.example",
  "crv": "P-256",
  "x": "PTTjIY84aLtaZCxLTrG_d8I0G6YKCV7lg8M4xkKfwQ4",
  "y": "ank6KA34vv24HZLXlChVs85NEGlpg2sbqNmR_BcgyJU"
}"""

JWK_EC_PUB_P384 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.384@hobbiton.example",
  "crv": "P-384",
  "x": "IDC-5s6FERlbC4Nc_4JhKW8sd51AhixtMdNUtPxhRFP323QY6cwWeIA3leyZhz-J",
  "y": "eovmN9ocANS8IJxDAGSuC1FehTq5ZFLJU7XSPg36zHpv4H2byKGEcCBiwT4sFJsy"
}"""

JWK_EC_PUB_P521 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.521@hobbiton.example",
  "crv": "P-521",
  "x": "AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt",
  "y": "AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVySsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1"
}"""

JWK_EC_PUB_SECP256K1 = """{
  "kty": "EC",
  "kid": "bilbo.baggins.256k@hobbiton.example",
  "crv": "secp256k1",
  "x": "MLnVyPDPQpNm0KaaO4iEh0i8JItHXJE0NcIe8GK1SYs",
  "y": "7r8d-xF7QAgT5kSRdly6M8xeg4Jz83Gs_CQPQRH65QI"
}"""

JWK_EMPTY_KEY = "{}"

JWK_HMAC_KEY = """{
     "kty": "oct",
     "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037",
     "use": "sig",
     "alg": "HS256",
     "k": "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
}"""

JWK_KEYSET_ONLY_UNKNOWN_ALG = """{"keys":[{"kid":"lYXxnemSzWNBUoPug_h0hZnjPi5oKCmQ9awQJaZCWWM","kty":"RSA","alg":"RSA-OAEP","use":"enc","n":"k75Ghd4r8h_fdydTAXyMjrGYNnuiG7yevoW1ZIIuegEUK3LLGY0Z3Q8PhCrkmi6LpkPwwR1C8ck9plvSs4vZ9GqmUoi5YcQEile6HjPG3NBwQ-cHWY4ZH_D-ItdzcZUKDxjHYaY-GW1yLeJ1RAh8wMPM7cenA2v0eNIq4HaIXzZJ2Hgxh4Ei-CSYcD0f_TYEySqUEb8jd0dC8frpkYDkOUCVizRBDUEg_hkPSpVqfLP8ekxIHxkC9wcfL-d2FhptxBQYN8NFnIuG9NFXbZ5mdzdmIuN6WPr_CECcgL9qXsph9U-L829dU67ufeBvzEejJ8qwiswslRdx4ZcYjtaBdQ","e":"AQAB","x5c":["MIICnTCCAYUCBgGAUN05KzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0aW5nMB4XDTIyMDQyMjEwNDAxN1oXDTMyMDQyMjEwNDE1N1owEjEQMA4GA1UEAwwHVGVzdGluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJO+RoXeK/If33cnUwF8jI6xmDZ7ohu8nr6FtWSCLnoBFCtyyxmNGd0PD4Qq5Joui6ZD8MEdQvHJPaZb0rOL2fRqplKIuWHEBIpXuh4zxtzQcEPnB1mOGR/w/iLXc3GVCg8Yx2GmPhltci3idUQIfMDDzO3HpwNr9HjSKuB2iF82Sdh4MYeBIvgkmHA9H/02BMkqlBG/I3dHQvH66ZGA5DlAlYs0QQ1BIP4ZD0qVanyz/HpMSB8ZAvcHHy/ndhYabcQUGDfDRZyLhvTRV22eZnc3ZiLjelj6/whAnIC/al7KYfVPi/NvXVOu7n3gb8xHoyfKsIrMLJUXceGXGI7WgXUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAeMUFrCX4eAfF8i6wILOP5dDJOBN10nPP63VNliQ7+YHu1ZI0VGB7TNrImRE9riH2IWenSXD21DxK31qBlZKNEgaH7rVwwvOZ22qCyWacv1+QdanxAiljD03rU7HOR/tyqcvjl6U2Yadxcq6OWlKKVaa0fNtbPigqAwQ3iVpg9N+OthANYyKHxlmzJKGeEaDA69/uJ6UwektHlv/9BnNFh8We6EwJxYG7/rejI02EgbJFxGO1RlcmigTxRc5l3Dw4WldBIRxWiJgSEkKSfUy5S7sQdFQokZjTyqy6h1ldb/tgrWLIE0srGQ2u/fQeSgPTbAzihaeOf+WKq5RDXoq5bw=="],"x5t":"FaWinuPZQiDMljn3x9DMAuepBYQ","x5t#S256":"_0B--Hh1KgNtdyZqAp1NWUAikRPvlt2HGm__xXpjTi0"}]}"""

JWK_KEYSET_WITH_UNKNOWN_ALG = """{"keys":[{"kid":"U1MayerhVuRj8xtFR8hyMH9lCfVMKlb3TG7mbQAS19M","kty":"RSA","alg":"RS256","use":"sig","n":"omef3NkXf4--6BtUPKjhlV7pf6Vv7HMg-VL-ITX8KQZTD4LTzWO3x9RPwVepKjgfvJe_IiZFaJX78-a7zpcG9mpZG8czp3C8nZSvAJKphvYLd9s9qYrGMFW9t1eHyGwmIQN02VXwHeZ0JDd5X4i7sO4XPkNycfzSoxaQbv7wANYBTcvcWcjYVxIj4ZpYkSsQqrrOTm69G7FyurtfExGc7jlSRcv-Gubq_K3IQLHGHTlil20wqZmis1dLJwpAjgTxY7uQSwEdqJHCJR3q76bsDelIBZpbR07kqIOXqYu52w0wkC_1W7_HcVPLNp6T_ML09P8jGsOWfMO95_zchkseQw","e":"AQAB","x5c":["MIICnTCCAYUCBgGAUN03JTANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0aW5nMB4XDTIyMDQyMjEwNDAxNloXDTMyMDQyMjEwNDE1NlowEjEQMA4GA1UEAwwHVGVzdGluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKJnn9zZF3+PvugbVDyo4ZVe6X+lb+xzIPlS/iE1/CkGUw+C081jt8fUT8FXqSo4H7yXvyImRWiV+/Pmu86XBvZqWRvHM6dwvJ2UrwCSqYb2C3fbPamKxjBVvbdXh8hsJiEDdNlV8B3mdCQ3eV+Iu7DuFz5DcnH80qMWkG7+8ADWAU3L3FnI2FcSI+GaWJErEKq6zk5uvRuxcrq7XxMRnO45UkXL/hrm6vytyECxxh05YpdtMKmZorNXSycKQI4E8WO7kEsBHaiRwiUd6u+m7A3pSAWaW0dO5KiDl6mLudsNMJAv9Vu/x3FTyzaek/zC9PT/IxrDlnzDvef83IZLHkMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAi7ZppYbkpt0ALn5NXIIPgA04svRwAmsUJWKLBS5iKVXq6HOJPsz0GAB9oKpjar83rUomwK2UE0XFJLMDvrB0nTZJBjm2DCANLL1GtTKUd+mdvhyHCIMrUApkhAYzv2Rk1c4+Jt7f5/h8FnM8jdl9FGc5TBy5ixS0OxnyW1JOakClYQz8vNS7LrC4hmLWwy7GAmUdemNLEefQcECaNzaLN5gGk1ht5lJyNCsHu9STZeYM2UXdDAtMtu9HAepfzh2CAOscSDtZr89SmFSwxKaOfbJyXH4PivMgWK4zO0P6ofuv8d8gRbUAUgnysKHQc0isTVWOxgmzI69EUe/iVXJHig=="],"x5t":"0C94xr3ayzaC9OUcSSLyrwDGdmI","x5t#S256":"O6ntIrYkVK0hX-_AwnrwJW1CO97lP3D2_aKnELuNLSo"},{"kid":"lYXxnemSzWNBUoPug_h0hZnjPi5oKCmQ9awQJaZCWWM","kty":"RSA","alg":"RSA-OAEP","use":"enc","n":"k75Ghd4r8h_fdydTAXyMjrGYNnuiG7yevoW1ZIIuegEUK3LLGY0Z3Q8PhCrkmi6LpkPwwR1C8ck9plvSs4vZ9GqmUoi5YcQEile6HjPG3NBwQ-cHWY4ZH_D-ItdzcZUKDxjHYaY-GW1yLeJ1RAh8wMPM7cenA2v0eNIq4HaIXzZJ2Hgxh4Ei-CSYcD0f_TYEySqUEb8jd0dC8frpkYDkOUCVizRBDUEg_hkPSpVqfLP8ekxIHxkC9wcfL-d2FhptxBQYN8NFnIuG9NFXbZ5mdzdmIuN6WPr_CECcgL9qXsph9U-L829dU67ufeBvzEejJ8qwiswslRdx4ZcYjtaBdQ","e":"AQAB","x5c":["MIICnTCCAYUCBgGAUN05KzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdUZXN0aW5nMB4XDTIyMDQyMjEwNDAxN1oXDTMyMDQyMjEwNDE1N1owEjEQMA4GA1UEAwwHVGVzdGluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJO+RoXeK/If33cnUwF8jI6xmDZ7ohu8nr6FtWSCLnoBFCtyyxmNGd0PD4Qq5Joui6ZD8MEdQvHJPaZb0rOL2fRqplKIuWHEBIpXuh4zxtzQcEPnB1mOGR/w/iLXc3GVCg8Yx2GmPhltci3idUQIfMDDzO3HpwNr9HjSKuB2iF82Sdh4MYeBIvgkmHA9H/02BMkqlBG/I3dHQvH66ZGA5DlAlYs0QQ1BIP4ZD0qVanyz/HpMSB8ZAvcHHy/ndhYabcQUGDfDRZyLhvTRV22eZnc3ZiLjelj6/whAnIC/al7KYfVPi/NvXVOu7n3gb8xHoyfKsIrMLJUXceGXGI7WgXUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAeMUFrCX4eAfF8i6wILOP5dDJOBN10nPP63VNliQ7+YHu1ZI0VGB7TNrImRE9riH2IWenSXD21DxK31qBlZKNEgaH7rVwwvOZ22qCyWacv1+QdanxAiljD03rU7HOR/tyqcvjl6U2Yadxcq6OWlKKVaa0fNtbPigqAwQ3iVpg9N+OthANYyKHxlmzJKGeEaDA69/uJ6UwektHlv/9BnNFh8We6EwJxYG7/rejI02EgbJFxGO1RlcmigTxRc5l3Dw4WldBIRxWiJgSEkKSfUy5S7sQdFQokZjTyqy6h1ldb/tgrWLIE0srGQ2u/fQeSgPTbAzihaeOf+WKq5RDXoq5bw=="],"x5t":"FaWinuPZQiDMljn3x9DMAuepBYQ","x5t#S256":"_0B--Hh1KgNtdyZqAp1NWUAikRPvlt2HGm__xXpjTi0"}]}"""

JWK_OKP_KEY_ED25519 = """{
  "kty":"OKP",
  "crv":"Ed25519",
  "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}"""

JWK_OKP_KEY_ED448 = """{
  "kty": "OKP",
  "kid": "sig_ed448_01",
  "crv": "Ed448",
  "use": "sig",
  "x": "kvqP7TzMosCQCpNcW8qY2HmVmpPYUEIGn-sQWQgoWlAZbWpnXpXqAT6yMoYA08pkJm7P_HKZoHwA",
  "d": "Zh5xx0r_0tq39xj-8jGuCwAA6wsDim2ME7cX_iXzqDRgPN8lsZZHu60AO7m31Fa4NtHO07eU63q8",
  "alg": "EdDSA"
}"""

JWK_OKP_PUB_ED25519 = """{
  "kty":"OKP",
  "crv":"Ed25519",
  "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
}"""

JWK_OKP_PUB_ED448 = """{
  "kty": "OKP",
  "kid": "sig_ed448_01",
  "crv": "Ed448",
  "use": "sig",
  "x": "kvqP7TzMosCQCpNcW8qY2HmVmpPYUEIGn-sQWQgoWlAZbWpnXpXqAT6yMoYA08pkJm7P_HKZoHwA",
  "alg": "EdDSA"
}"""

JWK_RSA_KEY = """{
     "kty": "RSA",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
     "e": "AQAB",
     "d": "bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78eiZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRldY7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-bMwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDjd18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOcOpBrQzwQ",
     "p": "3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nRaO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmGpeNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0k",
     "q": "uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0s7pFc",
     "dp": "B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX59ehik",
     "dq": "CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pErAMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJKbi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdKT1cYF8",
     "qi": "3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-NZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDhjJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpPz8aaI4"
}"""

JWK_RSA_PUB_KEY = """{
     "kty": "RSA",
     "kid": "bilbo.baggins@hobbiton.example",
     "use": "sig",
     "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
     "e": "AQAB"
}"""

TESTKEY2_RSA_PUB_PEM_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1tUH3/0v8fvLensHO1g2
6+U4r7jBg43DVOgqmXAWQa8ArAb4NfTrsYX8YkVhZZYwuLmKczRj0GhXUVY9iDbT
sIGmgG+ySj6eiREz5VLqofFkAvRZ6y7yNv8PIGgXEhQTiDDNIkHGaFNMvn/eZ54H
is70pdTjR5Ko+/y/wg71df1nb/5KwttSvy0YsTu/XpkduonPruYfAVRG3HK+3GZd
xTygLcdamwe9jj+kjxtXRlrXVMQiXGFSU8U6bjafWnQiQ9XzjxvygBt0ZD0kRorr
p74XGyQY5ThkN8DlpJbTTFsxOnBUAQz4zhohjobIGBRimi5yVlyLOwTlpaKGFC7O
7wIDAQAB
-----END PUBLIC KEY-----
"""

TESTKEY_EC_PRIV_KEY = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2nninfu2jMHDwAbn
9oERUhRADS6duQaJEadybLaa0YShRANCAAQfMBxRZKUYEdy5/fLdGI2tYj6kTr50
PZPt8jOD23rAR7dhtNpG1ojqopmH0AH5wEXadgk8nLCT4cAPK59Qp9Ek
-----END PRIVATE KEY-----
"""

TESTKEY_EC_PUB_KEY = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHzAcUWSlGBHcuf3y3RiNrWI+pE6+
dD2T7fIzg9t6wEe3YbTaRtaI6qKZh9AB+cBF2nYJPJywk+HADyufUKfRJA==
-----END PUBLIC KEY-----
"""

TESTKEY_EC_SECP192R1_PRIV_KEY = """
-----BEGIN PRIVATE KEY-----
MG8CAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQEEVTBTAgEBBBiON6kYcPu8ZUDRTu8W
eXJ2FmX7e9yq0hahNAMyAARHecLjkXWDUJfZ4wiFH61JpmonCYH1GpinVlqw68Sf
wtDHg2F6SifQEFC6VKj1ZXw=
-----END PRIVATE KEY-----
"""

TESTKEY_EC_SSH_PUB_KEY = """ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBB8wHFFkpRgR3Ln98t0Yja1iPqROvnQ9k+3yM4PbesBHt2G02kbWiOqimYfQAfnARdp2CTycsJPhwA8rn1Cn0SQ="""

TESTKEY_ED25519_PRIV = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBy9N4xfv/9qOiKrxwRKeGfO5ab6lSukKHbuC5vaJ1Mg
-----END PRIVATE KEY-----
"""

TESTKEY_ED25519_PRIV_PEM = """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJb2MBNIWqpJ2zwLlbw8JkHNPIBkFCv/g127aQI7dQ1Q
-----END PRIVATE KEY-----
"""

TESTKEY_ED25519_PUB = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4pK2dePGgctIAsh0H/tmUrLzx2Vc4Ltc8TN9nfuChG"""

TESTKEY_ED25519_PUB_PEM = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEASmyuOjH4q3bPqsOwf61G4jBH5L2g9kWnCDOp/7IOHKg=
-----END PUBLIC KEY-----
"""

TESTKEY_PKCS1_PUB_PEM = """
-----BEGIN RSA PUBLIC KEY-----
MIGHAoGBAOV/0Vl/5VdHcYpnILYzBGWo5JQVzo9wBkbxzjAStcAnTwvv1ZJTMXs6
fjz91f9hiMM4Z/5qNTE/EHlDWxVdj1pyRaQulZPUs0r9qJ02ogRRGLG3jjrzzbzF
yj/pdNBwym0UJYC/Jmn/kMLwGiWI2nfa9vM5SovqZiAy2FD7eOtVAgED
-----END RSA PUBLIC KEY-----
"""

TESTKEY_RSA_CER = """
-----BEGIN CERTIFICATE-----
MIIDhTCCAm2gAwIBAgIJANE4sir3EkX8MA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV
BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEPMA0GA1UEBwwGQXVzdGluMQ4wDAYDVQQK
DAVQeUpXVDEZMBcGA1UECwwQVGVzdCBDZXJ0aWZpY2F0ZTAeFw0xNTAzMTgwMTE2
MTRaFw0xODAzMTcwMTE2MTRaMFkxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh
czEPMA0GA1UEBwwGQXVzdGluMQ4wDAYDVQQKDAVQeUpXVDEZMBcGA1UECwwQVGVz
dCBDZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANR4
MwXyb9nDo0K8gsHvDRHpa4jkzRVimVIr3r1K0YZanJmSXQr7giUa/sQjfjpjvKsI
CSUffH3jbo8VYPifS7N/1DgOB3BfZ2B+mqlVxCwBPB5PwC78YveprNQw7gL0BmmG
fpQDcZb8XkBTmUm45M//ZofGi3hisKiS6d6fjoVAUKcLwFAD4PNvjlLYE1t50pY4
3ha9eAfKgJ3hknP8JdJ4vvtUkWVFxUqL83KkDpJWt1tu66y36w+i14I/07A7OLw9
T5yJtc3FXpyk+032CNe27Bvzv1nnMM9jZdfaS+4A6LDa7hd6ICVjatS8p/4oz0J5
Dy6WR8ob7osnGHCNw4kCAwEAAaNQME4wHQYDVR0OBBYEFDR6fVdFxZED6YMmD62W
LlBW+qEBMB8GA1UdIwQYMBaAFDR6fVdFxZED6YMmD62WLlBW+qEBMAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFwDNwm+lU/kGfWwiWM0Lv2aosXotoiG
TsBSWIn2iYphq0vzlgChcNocN9zkaOz3zc9pcREP6lyqHpE0OEbNucHHDdU1L2he
lLFOLOmkpP5fyPDXs9nKYhO8ygMByEonHm3K/VvCgrsSgJ3JuxMLUxnE55jQXGWV
OqYQNo2J5h93Zd2HTTe19jCz+bbWnRBP5VvLAAAo5YSmk3iroWSPWAKkWOOecJ2Q
/xnRyuWERsfvZiF/m9q7yDJ55LXVVm3Rufmy76SoTnJ2acap+XQNXBH/AxayeLUS
OYmHWH61dUcsQtwXYHYRB8TTtMIwUCXGmthXkDJydEfrGcD0y6APIh8=
-----END CERTIFICATE-----
"""

# A weak 1024-bit RSA Private Key (aws-lc-rs supports 2048+)
RSA_1024_PRIVATE_KEY = '''
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKSnBZRkyTCTyEYn
MeDPWVAXUV+OFfal2YfQQpbfr5qF4+yqvfWzQEBN9ktMxdWtvnChbTxdsZxGJisq
oUCwhz0BRwu2UpENMdEQQbUJVopeJ13YXJgDpX30hdTwzXWMZCA/gcziD65ZERGM
vZPUVbcsfOvCyfyuFRveTEsSn8tfAgMBAAECgYBcVY27egmZREa7kJ9YAu+DCpCH
lZabisZCc3fkQ+ymKw92WQnOD4eoiA/milcnTRfO8bfgcmp3yJ7+9hkXvecYWJ2g
xsbpzjLhSlw2f2mznAL5qcpL76PhvF5rZSbrnAp0AAlzcP6ERk1f0cB92KWYMjC6
GV8/cqeEptVaMtMnAQJBANGZYjMfzUH+TQ8d18bjUmul4Mku1lka+2XAlOwbseId
2vewfTxP/L9kudqSBNhJDpcGd7yDC1dEy61IjM1i+McCQQDJGl8lFMfhvLa7uWyA
v8NxSiuAKUI1vjaMGDndHRXIb2Uxi6F9gHcOPPYu/d3wUsEo9cEwVwqf/NedRij7
efCpAkBM7dUjGosFq8aww61M7GZ16D4m2TAHKGYZJKQEPO3/JiIWQwrUNi94OAoW
9P0ePUJDoDYWVKq27yMqiLRVNfxFAkAz8oT7TifnztihG1/EzkRNImykOYQp3821
WJix3k5/LQ9FwhzgD2wxmFu7fcZzytysmPbjZsiO1UBZFwOFGlWpAkBqhS7ogaaj
bJ5W6TY4UPI8jFsr1ykMZI+xiZmAhkuo8BIZOC8/hEwmUMQ2o7q2K3FsMZNQ+Qxq
lw6qarV2C1JN
-----END PRIVATE KEY-----
'''

TESTKEY_RSA_PRIV_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJd
CvuCJRr+xCN+OmO8qwgJJR98feNujxVg+J9Ls3/UOA4HcF9nYH6aqVXELAE8Hk/A
Lvxi96ms1DDuAvQGaYZ+lANxlvxeQFOZSbjkz/9mh8aLeGKwqJLp3p+OhUBQpwvA
UAPg82+OUtgTW3nSljjeFr14B8qAneGSc/wl0ni++1SRZUXFSovzcqQOkla3W27r
rLfrD6LXgj/TsDs4vD1PnIm1zcVenKT7TfYI17bsG_O/Wecwz2Nl19pL7gDosNru
F3ogJWNq1Lyn/ijPQnkPLpZHyhvuiycYcI3DiQIDAQABAoIBAQCt9uzwBZ0HVGQs
lGULnUu6SsC9iXlR9TVMTpdFrij4NODb7Tc5cs0QzJWkytrjvB4Se7XhK3KnMLyp
cvu/Fc7J3fRJIVN98t+V5pOD6rGAxlIPD4Vv8z6lQcw8wQNgb6WAaZriXh93XJNf
YBO2hSj0FU5CBZLUsxmqLQBIQ6RR/OUGAvThShouE9K4N0vKB2UPOCu5U+d5zS3W
44Q5uatxYiSHBTYIZDN4u27Nfo5WA+GTvFyeNsO6tNNWlYfRHSBtnm6SZDY/5i4J
fxP2JY0waM81KRvuHTazY571lHM/TTvFDRUX5nvHIu7GToBKahfVLf26NJuTZYXR
5c09GAXBAoGBAO7a9M/dvS6eDhyESYyCjP6w61jD7UYJ1fudaYFrDeqnaQ857Pz4
BcKx3KMmLFiDvuMgnVVj8RToBGfMV0zP7sDnuFRJnWYcOeU8e2sWGbZmWGWzv0SD
+AhppSZThU4mJ8aa/tgsepCHkJnfoX+3wN7S9NfGhM8GDGxTHJwBpxINAoGBAOO4
ZVtn9QEblmCX/Q5ejInl43Y9nRsfTy9lB9Lp1cyWCJ3eep6lzT60K3OZGVOuSgKQ
vZ/aClMCMbqsAAG4fKBjREA6p7k4/qaMApHQum8APCh9WPsKLaavxko8ZDc41kZt
hgKyUs2XOhW/BLjmzqwGryidvOfszDwhH7rNVmRtAoGBALYGdvrSaRHVsbtZtRM3
imuuOCx1Y6U0abZOx9Cw3PIukongAxLlkL5G/XX36WOrQxWkDUK930OnbXQM7ZrD
+5dW/8p8L09Zw2VHKmb5eK7gYA1hZim4yJTgrdL/Y1+jBDz+cagcfWsXZMNfAZxr
VLh628x0pVF/sof67pqVR9UhAoGBAMcQiLoQ9GJVhW1HMBYBnQVnCyJv1gjBo+0g
emhrtVQ0y6+FrtdExVjNEzboXPWD5Hq9oKY+aswJnQM8HH1kkr16SU2EeN437pQU
zKI/PtqN8AjNGp3JVgLioYp/pHOJofbLA10UGcJTMpmT9ELWsVA8P55X1a1AmYDu
y9f2bFE5AoGAdjo95mB0LVYikNPa+NgyDwLotLqrueb9IviMmn6zKHCwiOXReqXD
X9slB8RA15uv56bmN04O//NyVFcgJ2ef169GZHiRFIgIy0Pl8LYkMhCYKKhyqM7g
xN+SqGqDTKDC22j00S7jcvCaa1qadn1qbdfukZ4NXv7E2d/LO0Y2Kkc=
-----END RSA PRIVATE KEY-----
"""

TESTKEY_RSA_PUB_KEY = """ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUeDMF8m/Zw6NCvILB7w0R6WuI5M0VYplSK969StGGWpyZkl0K+4IlGv7EI346Y7yrCAklH3x9426PFWD4n0uzf9Q4DgdwX2dgfpqpVcQsATweT8Au/GL3qazUMO4C9AZphn6UA3GW/F5AU5lJuOTP/2aHxot4YrCokunen46FQFCnC8BQA+Dzb45S2BNbedKWON4WvXgHyoCd4ZJz/CXSeL77VJFlRcVKi/NypA6SVrdbbuust+sPoteCP9OwOzi8PU+cibXNxV6cpPtN9gjXtuwb879Z5zDPY2XX2kvuAOiw2u4XeiAlY2rUvKf+KM9CeQ8ulkfKG+6LJxhwjcOJ aasmundo@mair.local"""


import base64, json, decimal, sys

sys.path.append(__file__.rsplit("/", 2)[0])
import webtoken as wt

from webtoken.api_jwk import PyJWK
from webtoken.api_jws import PyJWS
from webtoken.algorithms import NoneAlgorithm
from webtoken import (load_pem_private_key, load_pem_public_key, load_ssh_public_key)
from webtoken import DecodeError, InvalidAlgorithmError, InvalidSignatureError, InvalidTokenError, RemovedInPyjwt3Warning

import pytest

has_crypto = True


#-  This resides in jwt.utils
def base64url_encode(input: bytes) -> bytes:
    return base64.urlsafe_b64encode(input).replace(b"=", b"")

def base64url_decode(input):

    if isinstance(input, str): input = input.encode("ascii")
    rem = len(input) % 4
    if rem > 0: input += b"=" * (4 - rem)
    return base64.urlsafe_b64decode(input)


#-  Test utils
def utc_timestamp():
    return timegm(datetime.now(tz=timezone.utc).utctimetuple())


@pytest.fixture
def jws():
    return PyJWS()


@pytest.fixture
def payload():
    """Creates a sample jws claimset for use as a payload during tests"""
    return b"hello world"


class TestJWS:

    def test_register_algo_does_not_allow_duplicate_registration(self, jws):
        jws.register_algorithm("AAA", NoneAlgorithm())

        with pytest.raises(ValueError):
            jws.register_algorithm("AAA", NoneAlgorithm())


    def test_register_algo_rejects_non_algorithm_obj(self, jws):
        with pytest.raises(TypeError):
            jws.register_algorithm("AAA123", {})


    def test_unregister_algo_removes_algorithm(self, jws):
        supported = jws.get_algorithms()
        assert "none" in supported
        assert "HS256" in supported

        jws.unregister_algorithm("HS256")

        supported = jws.get_algorithms()
        assert "HS256" not in supported


    def test_unregister_algo_throws_error_if_not_registered(self, jws):
        with pytest.raises(KeyError):
            jws.unregister_algorithm("AAA")


    def test_algo_parameter_removes_alg_from_algorithms_list(self, jws):
        assert "none" in jws.get_algorithms()
        assert "HS256" in jws.get_algorithms()

        jws = PyJWS(algorithms=["HS256"])
        assert "none" not in jws.get_algorithms()
        assert "HS256" in jws.get_algorithms()


    def test_override_options(self):
        jws = PyJWS(options={"verify_signature": False})

        assert not jws.options["verify_signature"]


    def test_non_object_options_dont_persist(self, jws, payload):
        token = jws.encode(payload, "secret")
        jws.decode(token, "secret", options={"verify_signature": False})
        assert jws.options["verify_signature"]


    def test_options_must_be_dict(self):
        pytest.raises(TypeError, PyJWS, options=object())
        pytest.raises((TypeError, ValueError), PyJWS, options=("something"))


    def test_encode_decode(self, jws, payload):
        secret = "secret"
        jws_message = jws.encode(payload, secret, algorithm="HS256")
        decoded_payload = jws.decode(jws_message, secret, algorithms=["HS256"])

        assert decoded_payload == payload


    def test_decode_fails_when_alg_is_not_on_method_algorithms_param(self, jws, payload):
        secret = "secret"
        jws_token = jws.encode(payload, secret, algorithm="HS256")
        jws.decode(jws_token, secret, algorithms=["HS256"])

        with pytest.raises(InvalidAlgorithmError):
            jws.decode(jws_token, secret, algorithms=["HS384"])


    def test_decode_works_with_unicode_token(self, jws):
        secret = "secret"
        unicode_jws = (
            "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        )

        jws.decode(unicode_jws, secret, algorithms=["HS256"])


    def test_decode_missing_segments_throws_exception(self, jws):
        secret = "secret"
        example_jws = "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9"  # Missing segment

        with pytest.raises(DecodeError) as context:
            jws.decode(example_jws, secret, algorithms=["HS256"])

        exception = context.value
        assert str(exception) == "Not enough segments"


    def test_decode_invalid_token_type_is_none(self, jws):
        example_jws = None
        example_secret = "secret"

        with pytest.raises(DecodeError) as context:
            jws.decode(example_jws, example_secret, algorithms=["HS256"])

        exception = context.value
        assert "Invalid token type" in str(exception)


    def test_decode_invalid_token_type_is_int(self, jws):
        example_jws = 123
        example_secret = "secret"

        with pytest.raises(DecodeError) as context:
            jws.decode(example_jws, example_secret, algorithms=["HS256"])

        exception = context.value
        assert "Invalid token type" in str(exception)


    def test_decode_with_non_mapping_header_throws_exception(self, jws):
        secret = "secret"
        example_jws = (
            "MQ"  # == 1
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        )

        with pytest.raises(DecodeError) as context:
            jws.decode(example_jws, secret, algorithms=["HS256"])

        exception = context.value
        assert str(exception) == "Invalid header string: must be a json object"


    def test_encode_default_algorithm(self, jws, payload):
        msg = jws.encode(payload, "secret")
        decoded = jws.decode_complete(msg, "secret", algorithms=["HS256"])
        assert decoded == {
            "header": {"alg": "HS256", "typ": "JWT"},
            "payload": payload,
            "signature": (
                b"H\x8a\xf4\xdf3:\xe1\xac\x16E\xd3\xeb\x00\xcf\xfa\xd5\x05\xac"
                b"e\xc8@\xb6\x00\xd5\xde\x9aa|s\xcfZB"
            ),
        }


    def test_encode_algorithm_param_should_be_case_sensitive(self, jws, payload):
        jws.encode(payload, "secret", algorithm="HS256")

        with pytest.raises(NotImplementedError) as context:
            jws.encode(payload, None, algorithm="hs256")

        exception = context.value
        assert str(exception) == "Algorithm not supported"


    def test_encode_with_headers_alg_none(self, jws, payload):
        msg = jws.encode(payload, key=None, headers={"alg": "none"})
        with pytest.raises(DecodeError) as context:
            jws.decode(msg, algorithms=["none"])
        assert str(context.value) == "Signature verification failed"


    def test_encode_with_headers_alg_es256(self, jws, payload):
        priv_key = load_pem_private_key(ec_priv_key, password=None)
        pub_key = load_pem_public_key(ec_pub_key)

        msg = jws.encode(payload, priv_key, headers={"alg": "ES256"})
        assert b"hello world" == jws.decode(msg, pub_key, algorithms=["ES256"])


    def test_encode_with_alg_hs256_and_headers_alg_es256(self, jws, payload):
        priv_key = load_pem_private_key(ec_priv_key, password=None)
        pub_key = load_pem_public_key(ec_pub_key)

        msg = jws.encode(payload, priv_key, algorithm="HS256", headers={"alg": "ES256"})
        assert b"hello world" == jws.decode(msg, pub_key, algorithms=["ES256"])


    def test_encode_with_jwk(self, jws, payload):
        jwk = PyJWK(
            {
                "kty": "oct",
                "alg": "HS256",
                "k": "c2VjcmV0",  # "secret"
            }
        )
        msg = jws.encode(payload, key=jwk)
        decoded = jws.decode_complete(msg, key=jwk, algorithms=["HS256"])
        assert decoded == {
            "header": {"alg": "HS256", "typ": "JWT"},
            "payload": payload,
            "signature": (
                b"H\x8a\xf4\xdf3:\xe1\xac\x16E\xd3\xeb\x00\xcf\xfa\xd5\x05\xac"
                b"e\xc8@\xb6\x00\xd5\xde\x9aa|s\xcfZB"
            ),
        }

    def test_decode_algorithm_param_should_be_case_sensitive(self, jws):
        example_jws = (
            "eyJhbGciOiJoczI1NiIsInR5cCI6IkpXVCJ9"  # alg = hs256
            ".eyJoZWxsbyI6IndvcmxkIn0"
            ".5R_FEPE7SW2dT9GgIxPgZATjFGXfUDOSwo7TtO_Kd_g"
        )

        with pytest.raises(InvalidAlgorithmError) as context:
            jws.decode(example_jws, "secret", algorithms=["hs256"])

        exception = context.value
        assert str(exception) == "Algorithm not supported"


    def test_bad_secret(self, jws, payload):
        right_secret = "foo"
        bad_secret = "bar"
        jws_message = jws.encode(payload, right_secret)

        with pytest.raises(DecodeError) as excinfo:
            # Backward compat for ticket #315
            jws.decode(jws_message, bad_secret, algorithms=["HS256"])
        assert "Signature verification failed" == str(excinfo.value)

        with pytest.raises(InvalidSignatureError) as excinfo:
            jws.decode(jws_message, bad_secret, algorithms=["HS256"])
        assert "Signature verification failed" == str(excinfo.value)


    def test_decodes_valid_jws(self, jws, payload):
        example_secret = "secret"
        example_jws = (
            b"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            b"aGVsbG8gd29ybGQ."
            b"gEW0pdU4kxPthjtehYdhxB9mMOGajt1xCKlGGXDJ8PM"
        )

        decoded_payload = jws.decode(example_jws, example_secret, algorithms=["HS256"])

        assert decoded_payload == payload


    def test_decodes_complete_valid_jws(self, jws, payload):
        example_secret = "secret"
        example_jws = (
            b"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            b"aGVsbG8gd29ybGQ."
            b"gEW0pdU4kxPthjtehYdhxB9mMOGajt1xCKlGGXDJ8PM"
        )

        decoded = jws.decode_complete(example_jws, example_secret, algorithms=["HS256"])

        assert decoded == {
            "header": {"alg": "HS256", "typ": "JWT"},
            "payload": payload,
            "signature": (
                b"\x80E\xb4\xa5\xd58\x93\x13\xed\x86;^\x85\x87a\xc4"
                b"\x1ff0\xe1\x9a\x8e\xddq\x08\xa9F\x19p\xc9\xf0\xf3"
            ),
        }

    def test_decodes_with_jwk(self, jws, payload):
        jwk = PyJWK(
            {
                "kty": "oct",
                "alg": "HS256",
                "k": "c2VjcmV0",  # "secret"
            }
        )
        example_jws = (
            b"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            b"aGVsbG8gd29ybGQ."
            b"gEW0pdU4kxPthjtehYdhxB9mMOGajt1xCKlGGXDJ8PM"
        )

        decoded_payload = jws.decode(example_jws, jwk, algorithms=["HS256"])

        assert decoded_payload == payload

    def test_decodes_with_jwk_and_no_algorithm(self, jws, payload):
        jwk = PyJWK(
            {
                "kty": "oct",
                "alg": "HS256",
                "k": "c2VjcmV0",  # "secret"
            }
        )
        example_jws = (
            b"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            b"aGVsbG8gd29ybGQ."
            b"gEW0pdU4kxPthjtehYdhxB9mMOGajt1xCKlGGXDJ8PM"
        )

        decoded_payload = jws.decode(example_jws, jwk)

        assert decoded_payload == payload


    def test_decodes_with_jwk_and_mismatched_algorithm(self, jws, payload):
        jwk = PyJWK(
            {
                "kty": "oct",
                "alg": "HS512",
                "k": "c2VjcmV0",  # "secret"
            }
        )
        example_jws = (
            b"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
            b"aGVsbG8gd29ybGQ."
            b"gEW0pdU4kxPthjtehYdhxB9mMOGajt1xCKlGGXDJ8PM"
        )

        with pytest.raises(InvalidAlgorithmError):
            jws.decode(example_jws, jwk)


    # 'Control' Elliptic Curve jws created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    def test_decodes_valid_es384_jws(self, jws):
        example_payload = {"hello": "world"}
        example_pubkey = load_pem_public_key(ec_pub_key)
        example_jws = (
            b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
            b"eyJoZWxsbyI6IndvcmxkIn0.TORyNQab_MoXM7DvNKaTwbrJr4UY"
            b"d2SsX8hhlnWelQFmPFSf_JzC2EbLnar92t-bXsDovzxp25ExazrVHkfPkQ"
        )
        decoded_payload = jws.decode(example_jws, example_pubkey, algorithms=["ES256"])
        json_payload = json.loads(decoded_payload)

        assert json_payload == example_payload


    # 'Control' RSA jws created by another library.
    # Used to test for regressions that could affect both
    # encoding / decoding operations equally (causing tests
    # to still pass).
    def test_decodes_valid_rs384_jws(self, jws):
        example_payload = {"hello": "world"}
        example_pubkey = rsa_pub_key
        example_jws = (
            b"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9"
            b".eyJoZWxsbyI6IndvcmxkIn0"
            b".yNQ3nI9vEDs7lEh-Cp81McPuiQ4ZRv6FL4evTYYAh1X"
            b"lRTTR3Cz8pPA9Stgso8Ra9xGB4X3rlra1c8Jz10nTUju"
            b"O06OMm7oXdrnxp1KIiAJDerWHkQ7l3dlizIk1bmMA457"
            b"W2fNzNfHViuED5ISM081dgf_a71qBwJ_yShMMrSOfxDx"
            b"mX9c4DjRogRJG8SM5PvpLqI_Cm9iQPGMvmYK7gzcq2cJ"
            b"urHRJDJHTqIdpLWXkY7zVikeen6FhuGyn060Dz9gYq9t"
            b"uwmrtSWCBUjiN8sqJ00CDgycxKqHfUndZbEAOjcCAhBr"
            b"qWW3mSVivUfubsYbwUdUG3fSRPjaUPcpe8A"
        )
        decoded_payload = jws.decode(example_jws, example_pubkey, algorithms=["RS384"])
        json_payload = json.loads(decoded_payload)

        assert json_payload == example_payload


    def test_load_verify_valid_jws(self, jws, payload):

        example_secret = "secret"
        example_jws = (
            b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            b"aGVsbG8gd29ybGQ."
            b"SIr03zM64awWRdPrAM_61QWsZchAtgDV3pphfHPPWkI"
        )

        decoded_payload = jws.decode(
            example_jws, key=example_secret, algorithms=["HS256"]
        )

        assert decoded_payload == payload


    def test_allow_skip_verification(self, jws, payload):

        right_secret = "foo"
        jws_message = jws.encode(payload, right_secret)
        decoded_payload = jws.decode(jws_message, options={"verify_signature": False})

        assert decoded_payload == payload


    def test_decode_with_optional_algorithms(self, jws):

        example_secret = "secret"
        example_jws = (
            b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            b"aGVsbG8gd29ybGQ."
            b"SIr03zM64awWRdPrAM_61QWsZchAtgDV3pphfHPPWkI"
        )

        with pytest.raises(DecodeError) as exc:
            jws.decode(example_jws, key=example_secret)

        assert (
            'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            in str(exc.value)
        )


    def test_decode_no_algorithms_verify_signature_false(self, jws):

        example_secret = "secret"
        example_jws = (
            b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            b"aGVsbG8gd29ybGQ."
            b"SIr03zM64awWRdPrAM_61QWsZchAtgDV3pphfHPPWkI"
        )

        jws.decode(
            example_jws,
            key=example_secret,
            options={"verify_signature": False},
        )


    def test_load_no_verification(self, jws, payload):

        right_secret = "foo"
        jws_message = jws.encode(payload, right_secret)

        decoded_payload = jws.decode(
            jws_message,
            key=None,
            algorithms=["HS256"],
            options={"verify_signature": False},
        )

        assert decoded_payload == payload


    def test_no_secret(self, jws, payload):

        right_secret = "foo"
        jws_message = jws.encode(payload, right_secret)

        with pytest.raises(DecodeError):
            jws.decode(jws_message, algorithms=["HS256"])


    def test_verify_signature_with_no_secret(self, jws, payload):
        right_secret = "foo"
        jws_message = jws.encode(payload, right_secret)

        with pytest.raises(DecodeError) as exc:
            jws.decode(jws_message, algorithms=["HS256"])

        assert "Signature verification" in str(exc.value)


    def test_verify_signature_with_no_algo_header_throws_exception(self, jws, payload):
        example_jws = b"e30.eyJhIjo1fQ.KEh186CjVw_Q8FadjJcaVnE7hO5Z9nHBbU8TgbhHcBY"

        with pytest.raises(InvalidAlgorithmError):
            jws.decode(example_jws, "secret", algorithms=["HS256"])


    def test_invalid_crypto_alg(self, jws, payload):
        with pytest.raises(NotImplementedError):
            jws.encode(payload, "secret", algorithm="HS1024")


    ## -- Nah
    # def test_missing_crypto_library_better_error_messages(self, jws, payload):
    #     with pytest.raises(NotImplementedError) as excinfo:
    #         jws.encode(payload, "secret", algorithm="RS256")
    #         assert "cryptography" in str(excinfo.value)


    def test_unicode_secret(self, jws, payload):
        secret = "\xc2"
        jws_message = jws.encode(payload, secret)
        decoded_payload = jws.decode(jws_message, secret, algorithms=["HS256"])

        assert decoded_payload == payload


    def test_nonascii_secret(self, jws, payload):
        secret = "\xc2"  # char value that ascii codec cannot decode
        jws_message = jws.encode(payload, secret)

        decoded_payload = jws.decode(jws_message, secret, algorithms=["HS256"])

        assert decoded_payload == payload


    def test_bytes_secret(self, jws, payload):
        secret = b"\xc2"  # char value that ascii codec cannot decode
        jws_message = jws.encode(payload, secret)

        decoded_payload = jws.decode(jws_message, secret, algorithms=["HS256"])

        assert decoded_payload == payload


    @pytest.mark.parametrize("sort_headers", (False, True))
    def test_sorting_of_headers(self, jws, payload, sort_headers):
        jws_message = jws.encode(
            payload,
            key="\xc2",
            headers={"b": "1", "a": "2"},
            sort_headers=sort_headers,
        )
        header_json = base64url_decode(jws_message.split(".")[0])
        assert sort_headers == (header_json.index(b'"a"') < header_json.index(b'"b"'))


    def test_decode_invalid_header_padding(self, jws):
        example_jws = (
            "aeyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        )
        example_secret = "secret"

        with pytest.raises(DecodeError) as exc:
            jws.decode(example_jws, example_secret, algorithms=["HS256"])

        assert "header padding" in str(exc.value)


    def test_decode_invalid_header_string(self, jws):
        example_jws = (
            "eyJhbGciOiAiSFMyNTbpIiwgInR5cCI6ICJKV1QifQ=="
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        )
        example_secret = "secret"

        with pytest.raises(DecodeError) as exc:
            jws.decode(example_jws, example_secret, algorithms=["HS256"])

        assert "Invalid header" in str(exc.value)

    def test_decode_invalid_payload_padding(self, jws):
        example_jws = (
            "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".aeyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".tvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        )
        example_secret = "secret"

        with pytest.raises(DecodeError) as exc:
            jws.decode(example_jws, example_secret, algorithms=["HS256"])

        assert "Invalid payload padding" in str(exc.value)


    def test_decode_invalid_crypto_padding(self, jws):
        example_jws = (
            "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
            ".eyJoZWxsbyI6ICJ3b3JsZCJ9"
            ".aatvagLDLoaiJKxOKqpBXSEGy7SYSifZhjntgm9ctpyj8"
        )
        example_secret = "secret"

        with pytest.raises(DecodeError) as exc:
            jws.decode(example_jws, example_secret, algorithms=["HS256"])

        assert "Invalid crypto padding" in str(exc.value)


    def test_decode_with_algo_none_should_fail(self, jws, payload):
        jws_message = jws.encode(payload, key=None, algorithm="none")

        with pytest.raises(DecodeError):
            jws.decode(jws_message, algorithms=["none"])


    def test_decode_with_algo_none_and_verify_false_should_pass(self, jws, payload):
        jws_message = jws.encode(payload, key=None, algorithm="none")
        jws.decode(jws_message, options={"verify_signature": False})


    def test_get_unverified_header_returns_header_values(self, jws, payload):
        jws_message = jws.encode(
            payload,
            key="secret",
            algorithm="HS256",
            headers={"kid": "toomanysecrets"},
        )

        header = jws.get_unverified_header(jws_message)

        assert "kid" in header
        assert header["kid"] == "toomanysecrets"


    def test_get_unverified_header_fails_on_bad_header_types(self, jws, payload):
        # Contains a bad kid value (int 123 instead of string)
        example_jws = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6MTIzfQ"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".vs2WY54jfpKP3JGC73Vq5YlMsqM5oTZ1ZydT77SiZSk"
        )

        with pytest.raises(InvalidTokenError) as exc:
            jws.get_unverified_header(example_jws)

        assert "Key ID header parameter must be a string" == str(exc.value)


    @pytest.mark.parametrize("algo", ["RS256", "RS384", "RS512",], )
    def test_encode_decode_rsa_related_algorithms(self, jws, payload, algo):
        # PEM-formatted RSA key
        priv_rsakey = load_pem_private_key(rsa_priv_key, password=None)
        jws_message = jws.encode(payload, priv_rsakey, algorithm=algo)

        pub_rsakey = load_ssh_public_key(rsa_pub_key)
        jws.decode(jws_message, pub_rsakey, algorithms=[algo])

        # string-formatted key
        priv_rsakey = load_pem_private_key(rsa_priv_key, password=None)
        jws_message = jws.encode(payload, priv_rsakey, algorithm=algo)

        pub_rsakey = load_ssh_public_key(rsa_pub_key)
        jws.decode(jws_message, pub_rsakey, algorithms=[algo])


    def test_rsa_related_algorithms(self, jws):
        jws = PyJWS()
        jws_algorithms = jws.get_algorithms()

        if has_crypto:
            assert "RS256" in jws_algorithms
            assert "RS384" in jws_algorithms
            assert "RS512" in jws_algorithms
            assert "PS256" in jws_algorithms
            assert "PS384" in jws_algorithms
            assert "PS512" in jws_algorithms

        else:
            assert "RS256" not in jws_algorithms
            assert "RS384" not in jws_algorithms
            assert "RS512" not in jws_algorithms
            assert "PS256" not in jws_algorithms
            assert "PS384" not in jws_algorithms
            assert "PS512" not in jws_algorithms


    ## - cryptography allows reating a valid signature with a mismatched curve, aws-lc-rs  doesn't
    # @pytest.mark.parametrize("algo", ["ES256", "ES256K", "ES384", "ES512",],)
    # def test_encode_decode_ecdsa_related_algorithms(self, jws, payload, algo):
    #     # PEM-formatted EC key
    #     priv_eckey = load_pem_private_key(ec_priv_key, password=None)
    #     jws_message = jws.encode(payload, priv_eckey, algorithm=algo)

    #     pub_eckey = load_pem_public_key(ec_pub_key)
    #     jws.decode(jws_message, pub_eckey, algorithms=[algo])

    #     # string-formatted key
    #     priv_eckey = ec_priv_key  # type: ignore[assignment]
    #     jws_message = jws.encode(payload, priv_eckey, algorithm=algo)

    #     pub_eckey = ec_pub_key  # type: ignore[assignment]
    #     jws.decode(jws_message, pub_eckey, algorithms=[algo])


    def test_ecdsa_related_algorithms(self, jws):
        jws = PyJWS()
        jws_algorithms = jws.get_algorithms()

        if has_crypto:
            assert "ES256" in jws_algorithms
            assert "ES256K" in jws_algorithms
            assert "ES384" in jws_algorithms
            assert "ES512" in jws_algorithms
        else:
            assert "ES256" not in jws_algorithms
            assert "ES256K" not in jws_algorithms
            assert "ES384" not in jws_algorithms
            assert "ES512" not in jws_algorithms


    def test_skip_check_signature(self, jws):
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzb21lIjoicGF5bG9hZCJ9"
            ".4twFt5NiznN84AWoo1d7KO1T_yoc0Z6XOpOVswacPZA"
        )
        jws.decode(token, "secret", options={"verify_signature": False})


    def test_decode_options_must_be_dict(self, jws, payload):
        token = jws.encode(payload, "secret")

        with pytest.raises(TypeError):
            jws.decode(token, "secret", options=object())

        with pytest.raises((TypeError, ValueError)):
            jws.decode(token, "secret", options="something")


    def test_custom_json_encoder(self, jws, payload):
        class CustomJSONEncoder(json.JSONEncoder):
            def default(self, o):
                assert isinstance(o, decimal.Decimal)
                return "it worked"

        data = {"some_decimal": decimal.Decimal("2.2")}

        with pytest.raises(TypeError):
            jws.encode(payload, "secret", headers=data)

        token = jws.encode(
            payload, "secret", headers=data, json_encoder=CustomJSONEncoder
        )

        header, *_ = token.split(".")
        header = json.loads(base64url_decode(header))

        assert "some_decimal" in header
        assert header["some_decimal"] == "it worked"


    def test_encode_headers_parameter_adds_headers(self, jws, payload):
        headers = {"testheader": True}
        token = jws.encode(payload, "secret", headers=headers)

        header = token[0 : token.index(".")].encode()
        header = base64url_decode(header)
        header = header.decode()

        header_obj = json.loads(header)

        assert "testheader" in header_obj
        assert header_obj["testheader"] == headers["testheader"]


    def test_encode_with_typ(self, jws):
        payload = """
        {
          "iss": "https://scim.example.com",
          "iat": 1458496404,
          "jti": "4d3559ec67504aaba65d40b0363faad8",
          "aud": [
            "https://scim.example.com/Feeds/98d52461fa5bbc879593b7754",
            "https://scim.example.com/Feeds/5d7604516b1d08641d7676ee7"
          ],
          "events": {
            "urn:ietf:params:scim:event:create": {
              "ref":
                  "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
              "attributes": ["id", "name", "userName", "password", "emails"]
            }
          }
        }
        """
        token = jws.encode(
            payload.encode("utf-8"), "secret", headers={"typ": "secevent+jwt"}
        )

        header = token[0 : token.index(".")].encode()
        header = base64url_decode(header)
        header_obj = json.loads(header)

        assert "typ" in header_obj
        assert header_obj["typ"] == "secevent+jwt"


    def test_encode_with_typ_empty_string(self, jws, payload):
        token = jws.encode(payload, "secret", headers={"typ": ""})

        header = token[0 : token.index(".")].encode()
        header = base64url_decode(header)
        header_obj = json.loads(header)

        assert "typ" not in header_obj


    def test_encode_with_typ_none(self, jws, payload):
        token = jws.encode(payload, "secret", headers={"typ": None})

        header = token[0 : token.index(".")].encode()
        header = base64url_decode(header)
        header_obj = json.loads(header)

        assert "typ" not in header_obj


    def test_encode_with_typ_without_keywords(self, jws, payload):
        headers = {"foo": "bar"}
        token = jws.encode(payload, "secret", "HS256", headers, None)

        header = token[0 : token.index(".")].encode()
        header = base64url_decode(header)
        header_obj = json.loads(header)

        assert "foo" in header_obj
        assert header_obj["foo"] == "bar"


    def test_encode_fails_on_invalid_kid_types(self, jws, payload):
        with pytest.raises(InvalidTokenError) as exc:
            jws.encode(payload, "secret", headers={"kid": 123})

        assert "Key ID header parameter must be a string" == str(exc.value)

        with pytest.raises(InvalidTokenError) as exc:
            jws.encode(payload, "secret", headers={"kid": None})

        assert "Key ID header parameter must be a string" == str(exc.value)


    def test_encode_decode_with_detached_content(self, jws, payload):
        secret = "secret"
        jws_message = jws.encode(
            payload, secret, algorithm="HS256", is_payload_detached=True
        )

        jws.decode(jws_message, secret, algorithms=["HS256"], detached_payload=payload)


    def test_encode_detached_content_with_b64_header(self, jws, payload):
        secret = "secret"

        # Check that detached content is automatically detected when b64 is false
        headers = {"b64": False}
        token = jws.encode(payload, secret, "HS256", headers)

        msg_header, msg_payload, _ = token.split(".")
        msg_header = base64url_decode(msg_header.encode())
        msg_header_obj = json.loads(msg_header)

        assert "b64" in msg_header_obj
        assert msg_header_obj["b64"] is False
        # Check that the payload is not inside the token
        assert not msg_payload

        # Check that content is not detached and b64 header removed when b64 is true
        headers = {"b64": True}
        token = jws.encode(payload, secret, "HS256", headers)

        msg_header, msg_payload, _ = token.split(".")
        msg_header = base64url_decode(msg_header.encode())
        msg_header_obj = json.loads(msg_header)

        assert "b64" not in msg_header_obj
        assert msg_payload


    def test_decode_detached_content_without_proper_argument(self, jws):
        example_jws = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2V9"
            "."
            ".65yNkX_ZH4A_6pHaTL_eI84OXOHtfl4K0k5UnlXZ8f4"
        )
        example_secret = "secret"

        with pytest.raises(DecodeError) as exc:
            jws.decode(example_jws, example_secret, algorithms=["HS256"])

        assert (
            'It is required that you pass in a value for the "detached_payload" argument to decode a message having the b64 header set to false.'
            in str(exc.value)
        )


    def test_decode_warns_on_unsupported_kwarg(self, jws, payload):
        secret = "secret"
        jws_message = jws.encode(
            payload, secret, algorithm="HS256", is_payload_detached=True
        )

        with pytest.warns(RemovedInPyjwt3Warning) as record:
            jws.decode(
                jws_message,
                secret,
                algorithms=["HS256"],
                detached_payload=payload,
                foo="bar",
            )
        assert len(record) == 1
        assert "foo" in str(record[0].message)


    def test_decode_complete_warns_on_unuspported_kwarg(self, jws, payload):
        secret = "secret"
        jws_message = jws.encode(
            payload, secret, algorithm="HS256", is_payload_detached=True
        )

        with pytest.warns(RemovedInPyjwt3Warning) as record:
            jws.decode_complete(
                jws_message,
                secret,
                algorithms=["HS256"],
                detached_payload=payload,
                foo="bar",
            )
        assert len(record) == 1
        assert "foo" in str(record[0].message)


ec_priv_key = b'''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2nninfu2jMHDwAbn
9oERUhRADS6duQaJEadybLaa0YShRANCAAQfMBxRZKUYEdy5/fLdGI2tYj6kTr50
PZPt8jOD23rAR7dhtNpG1ojqopmH0AH5wEXadgk8nLCT4cAPK59Qp9Ek
-----END PRIVATE KEY-----
'''


ec_pub_key = b'''
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHzAcUWSlGBHcuf3y3RiNrWI+pE6+
dD2T7fIzg9t6wEe3YbTaRtaI6qKZh9AB+cBF2nYJPJywk+HADyufUKfRJA==
-----END PUBLIC KEY-----
'''

rsa_priv_key = b'''
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA1HgzBfJv2cOjQryCwe8NEelriOTNFWKZUivevUrRhlqcmZJd
CvuCJRr+xCN+OmO8qwgJJR98feNujxVg+J9Ls3/UOA4HcF9nYH6aqVXELAE8Hk/A
Lvxi96ms1DDuAvQGaYZ+lANxlvxeQFOZSbjkz/9mh8aLeGKwqJLp3p+OhUBQpwvA
UAPg82+OUtgTW3nSljjeFr14B8qAneGSc/wl0ni++1SRZUXFSovzcqQOkla3W27r
rLfrD6LXgj/TsDs4vD1PnIm1zcVenKT7TfYI17bsG/O/Wecwz2Nl19pL7gDosNru
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
'''


rsa_pub_key = b'''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUeDMF8m/Zw6NCvILB7w0R6WuI5M0VYplSK969StGGWpyZkl0K+4IlGv7EI346Y7yrCAklH3x9426PFWD4n0uzf9Q4DgdwX2dgfpqpVcQsATweT8Au/GL3qazUMO4C9AZphn6UA3GW/F5AU5lJuOTP/2aHxot4YrCokunen46FQFCnC8BQA+Dzb45S2BNbedKWON4WvXgHyoCd4ZJz/CXSeL77VJFlRcVKi/NypA6SVrdbbuust+sPoteCP9OwOzi8PU+cibXNxV6cpPtN9gjXtuwb879Z5zDPY2XX2kvuAOiw2u4XeiAlY2rUvKf+KM9CeQ8ulkfKG+6LJxhwjcOJ aasmundo@mair.local'''





"""Test"""
import pytest

from myjwt.Exception import InvalidJwtJson
from myjwt.Exception import InvalidParam
from myjwt.Exception import UnknownAlg
from myjwt.modify_jwt import add_header
from myjwt.modify_jwt import add_payload
from myjwt.modify_jwt import change_alg
from myjwt.modify_jwt import change_payload
from myjwt.modify_jwt import signature
from myjwt.utils import HEADER
from myjwt.utils import jwt_to_json
from myjwt.utils import PAYLOAD
from myjwt.utils import SIGNATURE

invalid_jwt = "test.test"
jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6ImF6In0."
jwt_rsa = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6ImEifQ.Fjziy6GSQpP9tQRyko5APZjdymkQ8EJGOa"
    "-A2JQ6xcAVucXRhZbdBbAM2DG8io_brP_ROAqYaNlvRVsztXoPHFz_e7D2K0q6f02RXeRwZJGOhy0K"
    "-Oj9Z1UmFJWqVpAAafN75w7OKoSRh6BtQfH8XDleqwpVoywCuWFdYrSbqBoVskRQkp8H-HUC5XmN5om4"
    "-NdiQkiKa7OFQ6Hoklclz9_WD5rc"
    "-HWJp3rJW4EIHzOPfs1GuDuhtIRu0uuRYp4vvzLZcVm0BhlK9e_fmFcbsTz3MwVHIeFEIx2NjQdhE"
    "-CefQ4tNg6Rr6OtgGExToUfD0i0mAoAhTcvmoyO6c2paQ"
)
jwt_hs256 = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6ImEifQ.KJDuTWSj9wa3NL3j1u2HOijvgu"
    "-oO9tBjKGxjo_qdXQ"
)
encoded_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"
header = {"typ": "JWT", "alg": "none"}
add_header_value = {"kid": "1"}
payload = {"login": "az"}
add_payload_value = {"username": "az"}
signature_value = ""
jwt_json = {
    HEADER: header,
    PAYLOAD: payload,
    SIGNATURE: signature_value,
}
path = "./examples/05-rsa-hmac-confusion/public.pem"


def test_add_payload():
    """
    Test add_payload method in modify_jwt.py
    """
    with pytest.raises(InvalidJwtJson):
        add_payload({}, {})

    with pytest.raises(InvalidParam):
        add_payload(jwt_json, "")

    new_jwt_json = add_payload(jwt_json, add_payload_value)
    assert list(new_jwt_json[PAYLOAD].keys()) == ["login", "username"]
    assert new_jwt_json[PAYLOAD]["username"] == add_payload_value["username"]
    assert new_jwt_json[PAYLOAD]["login"] == payload["login"]

    assert new_jwt_json[HEADER] == jwt_json[HEADER]
    assert new_jwt_json[SIGNATURE] == jwt_json[SIGNATURE]


def test_add_header():
    """
    Test add_header method in modify_jwt.py
    """
    with pytest.raises(InvalidJwtJson):
        add_header({}, {})

    with pytest.raises(InvalidParam):
        add_header(jwt_json, "{}")

    new_jwt_json = add_header(jwt_json, add_header_value)
    assert list(new_jwt_json[HEADER].keys()), ["typ", "alg", "kid"]
    assert new_jwt_json[HEADER]["typ"] == header["typ"]
    assert new_jwt_json[HEADER]["alg"] == header["alg"]
    assert new_jwt_json[HEADER]["kid"] == add_header_value["kid"]

    assert new_jwt_json[PAYLOAD] == jwt_json[PAYLOAD]
    assert new_jwt_json[SIGNATURE] == jwt_json[SIGNATURE]


def test_change_alg():
    """
    Test changeAlg method in modify_jwt.py
    """
    with pytest.raises(InvalidJwtJson):
        change_alg({}, "test")

    new_jwt_json = change_alg(jwt_json, "test")
    assert new_jwt_json[HEADER]["alg"], "test"

    assert new_jwt_json[PAYLOAD] == jwt_json[PAYLOAD]
    assert new_jwt_json[SIGNATURE] == jwt_json[SIGNATURE]


def test_change_payload():
    """
    Test changePayload method in modify_jwt.py
    """
    with pytest.raises(InvalidJwtJson):
        change_payload({}, {})

    new_jwt_json = change_payload(jwt_json, add_payload_value)

    assert new_jwt_json[PAYLOAD] == jwt_json[PAYLOAD]

    assert new_jwt_json[HEADER] == jwt_json[HEADER]
    assert new_jwt_json[SIGNATURE] == jwt_json[SIGNATURE]


def test_signature():
    """
    Test signature method in modify_jwt.py
    """
    with pytest.raises(InvalidJwtJson):
        signature({}, "")

    jwt_json = {
        HEADER: {"typ": "JWT", "alg": "none"},
        PAYLOAD: {"login": "az"},
        SIGNATURE: "",
    }
    new_jwt = signature(jwt_json, "")
    assert new_jwt == jwt

    jwt_json_test = jwt_to_json(jwt_rsa)
    jwt_json_test = change_alg(jwt_json_test, "HS256")
    new_jwt = signature(jwt_json_test, open(path).read())
    assert new_jwt == jwt_hs256

    new_jwt_json = jwt_json
    new_jwt_json[HEADER]["alg"] = "unknowAlg"
    with pytest.raises(UnknownAlg):
        signature(new_jwt_json, "")

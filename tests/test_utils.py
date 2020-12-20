"""Test"""
import os

import pytest as pytest

from myjwt.Exception import InvalidJWT
from myjwt.Exception import InvalidJwtJson
from myjwt.utils import create_crt
from myjwt.utils import encode_jwt
from myjwt.utils import encoded_to_json
from myjwt.utils import HEADER
from myjwt.utils import is_valid_jwt
from myjwt.utils import is_valid_jwt_json
from myjwt.utils import jwt_to_json
from myjwt.utils import PAYLOAD
from myjwt.utils import SIGNATURE

invalid_jwt = "test.test"
jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6ImF6In0."
encoded_string = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"
header = {"typ": "JWT", "alg": "none"}
payload = {"login": "az"}
signature = ""
jwt_json = {
    HEADER: header,
    PAYLOAD: payload,
    SIGNATURE: signature,
}


def test_jwt_to_json_InvalidJWT():
    """
    Test jwt_to_json method when jwt is invalid in utils.py
    """
    with pytest.raises(InvalidJWT):
        jwt_to_json(invalid_jwt)


def test_jwt_to_json():
    """
    Test jwt_to_json method in utils.py
    """
    jwt_json = jwt_to_json(jwt)
    assert type(jwt_json) == dict

    assert list(jwt_json.keys()) == [HEADER, PAYLOAD, SIGNATURE]

    assert jwt_json[HEADER] == header
    assert jwt_json[PAYLOAD] == payload
    assert jwt_json[SIGNATURE] == ""


def test_encoded_to_json():
    """
    Test encoded_to_json method in utils.py
    """
    jsonDecoded = encoded_to_json(encoded_string)

    assert type(jsonDecoded) == dict
    assert jsonDecoded == header


def test_encode_jwt():
    """
    Test encode_jwt method in utils.py
    """
    with pytest.raises(InvalidJwtJson):
        encode_jwt({})

    new_jwt = encode_jwt(jwt_json)
    assert new_jwt + "." == jwt


def test_is_valid_jwt():
    """
    Test is_valid_jwt method in utils.py
    """
    assert is_valid_jwt(jwt)


def test_is_valid_jwt_json():
    """
    Test is_valid_jwt_json method in utils.py
    """
    assert is_valid_jwt_json(jwt_json)


def test_create_crt():
    """
    Test create_crt method in utils.py
    """
    create_crt()
    assert os.path.exists("selfsigned.crt")
    assert os.path.exists("private.pem")

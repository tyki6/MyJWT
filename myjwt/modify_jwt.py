"""
Package for modify your jwt(header, payload, signature)
"""

import base64
import hashlib
import hmac
from typing import Any

from myjwt.Exception import InvalidJwtJson, InvalidParam, UnknownAlg
from myjwt.utils import HEADER, PAYLOAD, encode_jwt, is_valid_jwt_json


def add_payload(jwt_json: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """
    Add new key:value to jwt's payload.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    payload: Dict
        add value to your payload.

    Returns
    -------
    Dict
        a new jwt in json format.

    Raises
    -------
    InvalidJwtJson
        if your jwt_json is not a Dict.

    InvalidParam
        if your payload is not a Dict.
    """
    if not is_valid_jwt_json(jwt_json):
        raise InvalidJwtJson("Invalid JWT json format")

    if type(payload) is not dict:
        raise InvalidParam("Invalid Payload")

    for payload_key in payload.keys():
        jwt_json[PAYLOAD][payload_key] = payload[payload_key]
    return jwt_json


def add_header(jwt_json: dict[str, Any], header: dict[str, Any]) -> dict[str, Any]:
    """
    Add new key:value to jwt's header.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    header: Dict
        add value to your header.

    Returns
    -------
    Dict
        a new jwt in json format.

    Raises
    -------
    InvalidJwtJson
        if your jwt_json is not a Dict.

    InvalidParam
        if your header is not a Dict.
    """
    if not is_valid_jwt_json(jwt_json):
        raise InvalidJwtJson("Invalid JWT json format")

    if type(header) is not dict:
        raise InvalidParam("Invalid Header")

    for header_key in header.keys():
        jwt_json[HEADER][header_key] = header[header_key]
    return jwt_json


def change_alg(jwt_json: dict[str, Any], algo: str) -> dict[str, Any]:
    """
    Change alg of your jwt.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    algo: str
        new algo.

    Returns
    -------
    Dict
        a new jwt in json format.

    Raises
    -------
    InvalidJwtJson
        if your jwt_json is not a Dict.
    """
    if not is_valid_jwt_json(jwt_json):
        raise InvalidJwtJson("Invalid JWT json format")

    jwt_json[HEADER]["alg"] = algo
    return jwt_json


def change_payload(jwt_json: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """
    Change the current payload to your jwt_json for the new payload given.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    payload: Dict
        new payload

    Returns
    -------
    Dict
        a new jwt in json format.

    Raises
    -------
    InvalidJwtJson
        if your jwt_json is not a Dict.
    """
    if not is_valid_jwt_json(jwt_json):
        raise InvalidJwtJson("Invalid JWT json format")
    jwt_json[PAYLOAD] = payload
    return jwt_json


def signature(jwt_json: dict[str, Any], key: str) -> str:
    """
    Sign your jwt.

    Parameters
    ----------
    jwt_json: Dict
        your jwt json (use encode_to_json.Check Doc).
    key: str
        key for dign your new jwt.

    Returns
    -------
    str
        new jwt.

    Raises
    -------
    InvalidJwtJson
        if your jwt_json is not a Dict.

    UnknownAlg
        if your alg is not a valid alg. Accepted: none, HS{256,384,512}.
    """
    if not is_valid_jwt_json(jwt_json):
        raise InvalidJwtJson("Invalid JWT json format")

    if jwt_json[HEADER]["alg"] == "none":
        return encode_jwt(jwt_json) + "."
    elif jwt_json[HEADER]["alg"] == "HS256":
        jwt = encode_jwt(jwt_json)
        signature_hmac = hmac.new(
            key.encode(),
            jwt.encode(),
            hashlib.sha256,
        ).digest()
        new_signature = base64.urlsafe_b64encode(signature_hmac).decode("UTF-8").strip("=")
        return jwt + "." + new_signature
    elif jwt_json[HEADER]["alg"] == "HS384":
        jwt = encode_jwt(jwt_json)
        signature_hmac = hmac.new(
            key.encode(),
            jwt.encode(),
            hashlib.sha384,
        ).digest()
        new_signature = base64.urlsafe_b64encode(signature_hmac).decode("UTF-8").strip("=")
        return jwt + "." + new_signature
    elif jwt_json[HEADER]["alg"] == "HS512":
        jwt = encode_jwt(jwt_json)
        signature_hmac = hmac.new(
            key.encode(),
            jwt.encode(),
            hashlib.sha512,
        ).digest()
        new_signature = base64.urlsafe_b64encode(signature_hmac).decode("UTF-8").strip("=")
        return jwt + "." + new_signature

    raise UnknownAlg(
        "Unknown alg " + jwt_json[HEADER]["alg"] + "send an issue please.",
    )

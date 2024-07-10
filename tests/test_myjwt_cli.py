"""Test"""

import json
import re
from typing import Any

import requests
from click.testing import CliRunner

from myjwt.modify_jwt import change_payload
from myjwt.myjwt_cli import myjwt_cli
from myjwt.utils import HEADER, PAYLOAD, SIGNATURE, jwt_to_json
from myjwt.variables import CHECK_DOCS, NOT_VALID_JWT, VALID_PAYLOAD_JSON

test_jwt = (
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
password_path = "./wordlist/common_pass.txt"
jwt_kid = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ"
    ".2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
)
kid_injection = "../../../../../../dev/null"

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


def test_error_cli() -> None:
    """
    Test error input during call in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [])
    assert result.exit_code == 2

    result = CliRunner().invoke(myjwt_cli, ["Peter"])
    assert NOT_VALID_JWT in result.output
    assert result.exit_code == 1


def test_payload() -> None:
    """
    Test Payload option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--full-payload"])
    assert result.exit_code, 2

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--full-payload", "test"],
    )
    assert VALID_PAYLOAD_JSON in result.output

    result = CliRunner().invoke(
        myjwt_cli,
        [
            test_jwt,
            "--full-payload",
            '{"username": "test", "password": "test"}',
        ],
    )
    jwtVerify = change_payload(
        jwt_to_json(test_jwt),
        json.loads('{"username": "test", "password": "test"}'),
    )
    regex = "new JWT: " + "(.*)"
    regex_search = re.search(regex, result.output)
    assert regex_search is not None
    jwt = regex_search.groups()[0]
    assert jwt_to_json(jwt) == jwtVerify
    assert result.exit_code == 0


def test_add_header() -> None:
    """
    Test add-header option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--add-header"])
    assert result.exit_code == 2

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--add-header", "admin"],
    )
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--add-header", "username=admin"],
    )
    regex = "new JWT: " + "(.*)"
    regex_search = re.search(regex, result.output)
    assert regex_search is not None
    jwt = regex_search.groups()[0]
    jwt_json = jwt_to_json(jwt)
    assert jwt_json[HEADER]["username"] == "admin"
    assert result.exit_code == 0


def test_add_payload() -> None:
    """
    Test add-payload option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--add-payload"])
    assert result.exit_code == 2

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--add-payload", "admin"],
    )
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--add-payload", "username=admin"],
    )
    regex = "new JWT: " + "(.*)"
    regex_search = re.search(regex, result.output)
    assert regex_search is not None
    jwt = regex_search.groups()[0]
    jwt_json = jwt_to_json(jwt)
    assert jwt_json[PAYLOAD]["username"] == "admin"
    assert result.exit_code == 0


def test_sign() -> None:
    """
    Test sign option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--sign"])
    assert result.exit_code == 2

    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--sign", "test"])
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [jwt_bruteforce, "--sign", "pentesterlab"],
    )
    regex = "new JWT: " + "(.*)"
    regex_search = re.search(regex, result.output)
    assert regex_search is not None
    jwt = regex_search.groups()[0]
    assert jwt_bruteforce == jwt
    assert result.exit_code == 0


def test_verify() -> None:
    """
    Test verify option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--verify"])
    assert result.exit_code == 2

    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--verify", "test"])
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [jwt_bruteforce, "--verify", "pentesterlab"],
    )
    assert "Valid Signature!!" in result.output
    assert result.exit_code == 0


def test_none_vulnerability() -> None:
    """
    Test none-vulnerability option in myjwt_cli.py
    """
    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--none-vulnerability"],
    )
    regex = "new JWT: " + "(.*)"
    regex_search = re.search(regex, result.output)
    assert regex_search is not None
    jwt = regex_search.groups()[0]
    assert "none" == jwt_to_json(jwt)[HEADER]["alg"]
    assert "" == jwt_to_json(jwt)[SIGNATURE]
    assert result.exit_code == 0


def test_hmac() -> None:
    """
    Test hmac option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--hmac"])
    assert result.exit_code == 2

    result = CliRunner().invoke(
        myjwt_cli,
        [
            test_jwt,
            "--hmac",
            "./examples/05-rsa-hmac-confusion/public.pem",
        ],
    )
    assert result.exit_code == 0


def test_bruteforce() -> None:
    """
    Test bruteforce option in myjwt_cli.py
    """
    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--bruteforce", "azdzd"],
    )
    assert result.exit_code, 2

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "--bruteforce", password_path],
    )
    assert CHECK_DOCS in result.output
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [jwt_bruteforce, "--bruteforce", "./wordlist/empty.txt"],
    )
    assert "JWT not cracked sorry. " in result.output
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [jwt_bruteforce, "--bruteforce", password_path],
    )
    assert "JWT cracked, key is: " + "pentesterlab" in result.output
    assert result.exit_code == 0


def test_kid() -> None:
    """
    Test kid option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--kid"])
    assert result.exit_code == 2

    result = CliRunner().invoke(
        myjwt_cli,
        [jwt_kid, "--kid", kid_injection],
    )
    assert result.exit_code == 0


def test_print() -> None:
    """
    Test print option in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt, "--print"])
    assert result.exit_code == 0


def test_url(requests_mock: Any) -> None:
    """
    Test url option in myjwt_cli.py
    """
    status_code = 200
    requests_mock.get(
        "http://localhost:8080",
        json={},
        status_code=status_code,
    )

    result = CliRunner().invoke(
        myjwt_cli,
        [
            test_jwt,
            "-u",
            "http://localhost:8080",
            "-c",
            "data=data",
            "-d",
            "data=data",
        ],
    )
    assert result.exit_code == 0

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "-u", "http://localhost:8080", "-c", "data"],
    )
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "-u", "http://localhost:8080", "-d", "data"],
    )
    assert result.exit_code == 1

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "-u", "http://localhost:8080", "-d", "data=MY_JWT"],
    )
    assert result.exit_code == 0

    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "-u", "http://localhost:8080", "-c", "data=MY_JWT"],
    )
    assert result.exit_code == 0


def test_url_connectionError(mocker: Any) -> None:
    """
    Test url error for url option in myjwt_cli.py
    """
    mocker.patch(
        "myjwt.vulnerabilities.send_jwt_to_url",
        side_effect=requests.exceptions.ConnectionError,
    )
    result = CliRunner().invoke(
        myjwt_cli,
        [test_jwt, "-u", "http://www.azdazdazdzadazdazdzad.com"],
    )
    assert "Connection Error. Verify your url" in result.output
    assert result.exit_code == 1


def test_jku(requests_mock: Any) -> None:
    """
    Test jku option in myjwt_cli.py
    """
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

    result = CliRunner().invoke(
        myjwt_cli,
        [jwt_jku, "--jku", "http://localhost:8080"],
    )
    assert result.exit_code == 0


def test_user_interface() -> None:
    """
    Test user_interface in myjwt_cli.py
    """
    result = CliRunner().invoke(myjwt_cli, [test_jwt])
    # raise UnsupportedOperation(stdin is not a terminal)
    assert isinstance(result.exception, SystemExit)


def test_x5c(requests_mock: Any) -> None:
    """
    Test x5c option in myjwt_cli.py
    """
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

    result = CliRunner().invoke(
        myjwt_cli,
        [jwt_x5u, "--x5u", "http://test.com"],
    )
    assert result.exit_code == 0

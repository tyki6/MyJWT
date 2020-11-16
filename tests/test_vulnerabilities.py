import os
import OpenSSL
import requests_mock

from unittest import TestCase

from MyJWT.Exception import InvalidJWT
from MyJWT.utils import HEADER, SIGNATURE, PAYLOAD, jwtToJson, createCrt
from MyJWT.vulnerabilities import (
    noneVulnerability,
    confusionRsaHmac,
    bruteforceDict,
    injectSqlKid,
    printDecoded,
    sendJwtToUrl,
    jkuVulnerability, x5uVulnerability)


class TestVulnerabilities(TestCase):
    def setUp(self):
        self.jwt = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6ImEifQ.Fjziy6GSQpP9tQRyko5APZjdymkQ8EJGOa"
            "-A2JQ6xcAVucXRhZbdBbAM2DG8io_brP_ROAqYaNlvRVsztXoPHFz_e7D2K0q6f02RXeRwZJGOhy0K"
            "-Oj9Z1UmFJWqVpAAafN75w7OKoSRh6BtQfH8XDleqwpVoywCuWFdYrSbqBoVskRQkp8H-HUC5XmN5om4"
            "-NdiQkiKa7OFQ6Hoklclz9_WD5rc"
            "-HWJp3rJW4EIHzOPfs1GuDuhtIRu0uuRYp4vvzLZcVm0BhlK9e_fmFcbsTz3MwVHIeFEIx2NjQdhE"
            "-CefQ4tNg6Rr6OtgGExToUfD0i0mAoAhTcvmoyO6c2paQ"
        )
        self.jwtBruteForce = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ"
            ".Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
        )
        self.jwtKid = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ"
            ".2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
        )
        self.jwtJku = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9.eyJ1c2VyIjoiYSJ9"
            ".e1oZ73Q95aYPcRfulEY--beuGEV2tE1W_FGHtH1ZlevC76lBVqbdM5PY1v6quuJWRtNLwqDbUdydAH4lubgE0pwix-A7LqcD-b"
            "-0mNQkt9jXqBYCYBsZtGnvBFB9qHoK_CI39qLku1rOWkcEOcJYMSJFfxipImBb_AwoiXv"
            "-wmnpchTOAY_PFOtXVXKHkoGQtEaMKfnRBXHAgyEAcqHCqvljWuMmdKVpyGNVaQBnKCEKkGyYLpdpL2UIZ3XNYy96JcGpm6LHvIXm6r"
            "EOkWoJl2j_07xVsM2S__QzllRw_qezS5rzuYlRz-0j0nP_S5gSRcdrR4yNtSO3ivue5mR-RQ"
        )
        self.jwtX5u = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHA6Ly90ZXN0LmNvbSJ9.eyJ1c2VyIjoiaGFja2VyIn0.Z57BGf-BW"
            "WGCYGRST3PstC7dqFVxLpYh8D9iy6z8_tpz8vIESa5IdLt3hkM8ysB0IjrkWbgNMYTaP7YiGpHG7MhF_IAc_q8HOilMtvrVTyJ0EpE3uJ"
            "okXZSh_hhU5ay2K8H743AG_5x7coAf7ZsNe_rnSuDN6iV_oXo31H2ga9VMk2BLgvqFLYgIYVETeQbcSx4M2rxiH20VbqO4dwzYDedYkD"
            "AHKGHUAI0eXJoJ7Sq3sDrjZ9_THTiHSwQQYFnlIbIcFKuANdExuhG-tmIhfa6-8Zu_RELLL6UzgL2G-yu021B_Hm9YmwuXewtDktXKY"
            "uWofo-PVFUUWVSEw7gIAw"
        )
        self.key = "pentesterlab"
        self.path = "./examples/05-rsa-hmac-confusion/public.pem"
        self.password = "./wordlist/common_pass.txt"
        self.signature = "KJDuTWSj9wa3NL3j1u2HOijvgu-oO9tBjKGxjo_qdXQ"
        self.injection = "../../../../../../dev/null"

    def testNoneVulnerability(self):
        with self.assertRaises(InvalidJWT):
            noneVulnerability("")

        newJwt = noneVulnerability(self.jwt)
        jwtJson = jwtToJson(self.jwt)
        newJwtJson = jwtToJson(newJwt)

        self.assertEqual(jwtJson[PAYLOAD], newJwtJson[PAYLOAD])
        self.assertEqual(newJwtJson[HEADER]["alg"], "none")
        self.assertEqual(newJwtJson[SIGNATURE], "")

    def testConfusionRsaHmac(self):
        with self.assertRaises(InvalidJWT):
            confusionRsaHmac("", self.path)

        newJwt = confusionRsaHmac(self.jwt, self.path)
        jwtJson = jwtToJson(self.jwt)
        newJwtJson = jwtToJson(newJwt)

        self.assertEqual(jwtJson[PAYLOAD], newJwtJson[PAYLOAD])
        self.assertEqual(newJwtJson[HEADER]["alg"], "HS256")
        self.assertEqual(newJwtJson[SIGNATURE], self.signature)

    def testBruteForceDict(self):
        with self.assertRaises(InvalidJWT):
            bruteforceDict("", self.password)

        key = bruteforceDict(self.jwtBruteForce, self.password)
        self.assertEqual(key, self.key)

        key = bruteforceDict(self.jwtBruteForce, "./wordlist/empty.txt")
        self.assertEqual(key, "")

    def testInjectSqlKid(self):
        with self.assertRaises(InvalidJWT):
            injectSqlKid("", self.injection)

        jwt = injectSqlKid(self.jwtKid, self.injection)
        self.assertEqual(jwtToJson(jwt)[HEADER]["kid"], self.injection)

    def testPrintDecoded(self):
        with self.assertRaises(InvalidJWT):
            printDecoded("")
        printDecoded(self.jwtBruteForce)

    @requests_mock.mock()
    def testSendJwtToUrl(self, m):
        status_code = 200
        m.get("http://localhost:8080", json={}, status_code=status_code)

        response = sendJwtToUrl(
            "http://localhost:8080",
            "GET",
            {"data": "data"},
            {"cookie": "cookie"},
            "test",
        )
        self.assertEqual(response.request.method, "GET")
        self.assertEqual(response.request.json(), {"data": "data"})

        status_code = 200
        m.post("http://localhost:8080", json={}, status_code=status_code)
        response = sendJwtToUrl(
            "http://localhost:8080",
            "POST",
            {"data": "data"},
            {"cookie": "cookie"},
            "test",
        )
        self.assertEqual(response.request.method, "POST")
        self.assertEqual(response.request.json(), {"data": "data"})
        self.assertEqual(response.request.headers["Authorization"], "Bearer test")

    @requests_mock.mock()
    def testJkuVulnerability(self, m):
        with self.assertRaises(InvalidJWT):
            jkuVulnerability("", "http://test.com")

        with self.assertRaises(InvalidJWT):
            jkuVulnerability(self.jwtBruteForce, "http://test.com")

        status_code = 200
        m.get("http://localhost:8080", json={
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
                    "alg": "RS256"
                }
            ]
        }, status_code=status_code)
        jwt = jkuVulnerability(self.jwtJku, "http://test.com")
        jwtJson = jwtToJson(jwt)
        self.assertIn("jku", jwtJson[HEADER])
        self.assertTrue(os.path.exists("jwk-python.json"))
        self.assertTrue(jwtJson[HEADER]["jku"], "http://test.com/jwk-python.json")

        jwt = jkuVulnerability(self.jwtJku, "http://test.com", file="test")
        jwtJson = jwtToJson(jwt)
        self.assertIn("jku", jwtJson[HEADER])
        self.assertTrue(os.path.exists("test.json"))
        self.assertTrue(jwtJson[HEADER]["jku"], "http://test.com/test.json")

        privatekey = OpenSSL.crypto.PKey()
        privatekey.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

        with open('private.pem', 'w') as f:
            f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, privatekey).decode())

        jkuVulnerability(self.jwtJku, "http://test.com", file="test", pem="private.pem")
        self.assertTrue(os.path.exists("private.pem"))

    @requests_mock.mock()
    def testX5uVulnerability(self, m):
        with self.assertRaises(InvalidJWT):
            x5uVulnerability("", url="http://test.com")

        with self.assertRaises(InvalidJWT):
            x5uVulnerability(self.jwtBruteForce, url="http://test.com")

        status_code = 200
        m.get("http://test.com", json={
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
                    "alg": "RS256"
                }
            ]
        }, status_code=status_code)
        jwt = x5uVulnerability(self.jwtX5u, url="http://test.com/jwks_with_x5c.json")
        jwtJson = jwtToJson(jwt)
        self.assertIn("x5u", jwtJson[HEADER])
        self.assertTrue(os.path.exists("jwks_with_x5c.json"))
        self.assertTrue(jwtJson[HEADER]["x5u"], "http://test.com/jwks_with_x5c.json")

        createCrt()

        x5uVulnerability(self.jwtX5u, url="http://test.com", crt="selfsigned.crt", pem="private.pem")
        self.assertTrue(os.path.exists("private.pem"))
        self.assertTrue(os.path.exists("selfsigned.crt"))

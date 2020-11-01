from unittest import TestCase

from MyJWT.Exception import InvalidJWT
from MyJWT.utils import HEADER, SIGNATURE, PAYLOAD, jwtToJson
from MyJWT.vulnerabilities import noneVulnerability, confusionRsaHmac, bruteforceDict, injectSqlKid, printDecoded, \
    sendJwtToUrl

import requests_mock


class TestVulnerabilities(TestCase):

    def setUp(self):
        self.jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6ImEifQ.Fjziy6GSQpP9tQRyko5APZjdymkQ8EJGOa" \
                   "-A2JQ6xcAVucXRhZbdBbAM2DG8io_brP_ROAqYaNlvRVsztXoPHFz_e7D2K0q6f02RXeRwZJGOhy0K" \
                   "-Oj9Z1UmFJWqVpAAafN75w7OKoSRh6BtQfH8XDleqwpVoywCuWFdYrSbqBoVskRQkp8H-HUC5XmN5om4" \
                   "-NdiQkiKa7OFQ6Hoklclz9_WD5rc" \
                   "-HWJp3rJW4EIHzOPfs1GuDuhtIRu0uuRYp4vvzLZcVm0BhlK9e_fmFcbsTz3MwVHIeFEIx2NjQdhE" \
                   "-CefQ4tNg6Rr6OtgGExToUfD0i0mAoAhTcvmoyO6c2paQ"
        self.jwtBruteForce = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ" \
                             ".Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
        self.jwtKid = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ" \
                      ".2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
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

        response = sendJwtToUrl("http://localhost:8080", "GET", {"data":"data"}, {"cookie":"cookie"}, "test")
        self.assertEqual(response.request.method, "GET")
        self.assertEqual(response.request.json(), {"data":"data"})

        status_code = 200
        m.post("http://localhost:8080", json={}, status_code=status_code)
        response = sendJwtToUrl("http://localhost:8080", "POST", {"data": "data"}, {"cookie": "cookie"}, "test")
        self.assertEqual(response.request.method, "POST")
        self.assertEqual(response.request.json(), {"data": "data"})
        self.assertEqual(response.request.headers["Authorization"], "Bearer test")

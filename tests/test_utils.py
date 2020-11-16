import os
from unittest import TestCase

from MyJWT.Exception import InvalidJWT, InvalidJwtJson
from MyJWT.utils import (
    jwtToJson,
    encodedToJson,
    encodeJwt,
    isValidJwt,
    isValidJwtJson,
    HEADER,
    PAYLOAD,
    SIGNATURE,
    createCrt)


class TestUtils(TestCase):
    def setUp(self):
        self.invalidJWT = "test.test"
        self.jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6ImF6In0."
        self.encodedString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"
        self.header = {"typ": "JWT", "alg": "none"}
        self.payload = {"login": "az"}
        self.signature = ""
        self.jwtJson = {
            HEADER: self.header,
            PAYLOAD: self.payload,
            SIGNATURE: self.signature,
        }

    def testJwtToJsonInvalidJWT(self):
        with self.assertRaises(InvalidJWT):
            jwtToJson(self.invalidJWT)

    def testJwtToJson(self):
        jwtJson = jwtToJson(self.jwt)
        self.assertIsInstance(jwtJson, dict)

        self.assertListEqual(list(jwtJson.keys()), [HEADER, PAYLOAD, SIGNATURE])

        self.assertEqual(jwtJson[HEADER], self.header)
        self.assertEqual(jwtJson[PAYLOAD], self.payload)
        self.assertEqual(jwtJson[SIGNATURE], "")

    def testEncodedToJson(self):
        jsonDecoded = encodedToJson(self.encodedString)

        self.assertIsInstance(jsonDecoded, dict)
        self.assertEqual(jsonDecoded, self.header)

    def testEncodeJwt(self):
        with self.assertRaises(InvalidJwtJson):
            encodeJwt({})

        jwt = encodeJwt(self.jwtJson)
        self.assertEqual(jwt + ".", self.jwt)

    def testIsvalidJwt(self):
        self.assertTrue(isValidJwt(self.jwt))

    def testIsValidJwtJson(self):
        self.assertTrue(isValidJwtJson(self.jwtJson))

    def testCreatCrt(self):
        createCrt()
        self.assertTrue(os.path.exists("selfsigned.crt"))
        self.assertTrue(os.path.exists("private.pem"))

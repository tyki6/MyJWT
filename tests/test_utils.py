"""Test"""
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
    createCrt,
)


class TestUtils(TestCase):
    """Test Class for utils.py"""

    def setUp(self):
        """ SetUp """
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
        """
        Test jwtToJson method when jwt is invalid in utils.py
        """
        with self.assertRaises(InvalidJWT):
            jwtToJson(self.invalidJWT)

    def testJwtToJson(self):
        """
        Test jwtToJson method in utils.py
        """
        jwtJson = jwtToJson(self.jwt)
        self.assertIsInstance(jwtJson, dict)

        self.assertListEqual(list(jwtJson.keys()), [HEADER, PAYLOAD, SIGNATURE])

        self.assertEqual(jwtJson[HEADER], self.header)
        self.assertEqual(jwtJson[PAYLOAD], self.payload)
        self.assertEqual(jwtJson[SIGNATURE], "")

    def testEncodedToJson(self):
        """
        Test encodedToJson method in utils.py
        """
        jsonDecoded = encodedToJson(self.encodedString)

        self.assertIsInstance(jsonDecoded, dict)
        self.assertEqual(jsonDecoded, self.header)

    def testEncodeJwt(self):
        """
         Test encodeJwt method in utils.py
         """
        with self.assertRaises(InvalidJwtJson):
            encodeJwt({})

        jwt = encodeJwt(self.jwtJson)
        self.assertEqual(jwt + ".", self.jwt)

    def testIsvalidJwt(self):
        """
         Test isValidJwt method in utils.py
         """
        self.assertTrue(isValidJwt(self.jwt))

    def testIsValidJwtJson(self):
        """
         Test isValidJwtJson method in utils.py
         """
        self.assertTrue(isValidJwtJson(self.jwtJson))

    def testCreatCrt(self):
        """
         Test createCrt method in utils.py
         """
        createCrt()
        self.assertTrue(os.path.exists("selfsigned.crt"))
        self.assertTrue(os.path.exists("private.pem"))

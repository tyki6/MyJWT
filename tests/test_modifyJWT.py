from unittest import TestCase
from MyJWT.Exception import InvalidJwtJson, InvalidParam, UnknownAlg
from MyJWT.modifyJWT import addpayload, addheader, changeAlg, changePayload, signature
from MyJWT.utils import HEADER, PAYLOAD, SIGNATURE, jwtToJson


class TestModifyJWT(TestCase):
    def setUp(self):
        self.invalidJWT = "test.test"
        self.jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJsb2dpbiI6ImF6In0."
        self.jwtRsa = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6ImEifQ.Fjziy6GSQpP9tQRyko5APZjdymkQ8EJGOa"
            "-A2JQ6xcAVucXRhZbdBbAM2DG8io_brP_ROAqYaNlvRVsztXoPHFz_e7D2K0q6f02RXeRwZJGOhy0K"
            "-Oj9Z1UmFJWqVpAAafN75w7OKoSRh6BtQfH8XDleqwpVoywCuWFdYrSbqBoVskRQkp8H-HUC5XmN5om4"
            "-NdiQkiKa7OFQ6Hoklclz9_WD5rc"
            "-HWJp3rJW4EIHzOPfs1GuDuhtIRu0uuRYp4vvzLZcVm0BhlK9e_fmFcbsTz3MwVHIeFEIx2NjQdhE"
            "-CefQ4tNg6Rr6OtgGExToUfD0i0mAoAhTcvmoyO6c2paQ"
        )
        self.jwtHs256 = (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6ImEifQ.KJDuTWSj9wa3NL3j1u2HOijvgu"
            "-oO9tBjKGxjo_qdXQ"
        )
        self.encodedString = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0"
        self.header = {"typ": "JWT", "alg": "none"}
        self.addHeader = {"kid": "1"}
        self.payload = {"login": "az"}
        self.addPayload = {"username": "az"}
        self.signature = ""
        self.jwtJson = {
            HEADER: self.header,
            PAYLOAD: self.payload,
            SIGNATURE: self.signature,
        }
        self.path = "./examples/05-rsa-hmac-confusion/public.pem"

    def testAddPayload(self):
        with self.assertRaises(InvalidJwtJson):
            addpayload({}, {})

        with self.assertRaises(InvalidParam):
            addpayload(self.jwtJson, "")

        newJwtJson = addpayload(self.jwtJson, self.addPayload)
        self.assertListEqual(list(newJwtJson[PAYLOAD].keys()), ["login", "username"])
        self.assertEqual(newJwtJson[PAYLOAD]["username"], self.addPayload["username"])
        self.assertEqual(newJwtJson[PAYLOAD]["login"], self.payload["login"])

        self.assertEqual(newJwtJson[HEADER], self.jwtJson[HEADER])
        self.assertEqual(newJwtJson[SIGNATURE], self.jwtJson[SIGNATURE])

    def testAddHeader(self):
        with self.assertRaises(InvalidJwtJson):
            addheader({}, {})

        with self.assertRaises(InvalidParam):
            addheader(self.jwtJson, "{}")

        newJwtJson = addheader(self.jwtJson, self.addHeader)
        self.assertListEqual(list(newJwtJson[HEADER].keys()), ["typ", "alg", "kid"])
        self.assertEqual(newJwtJson[HEADER]["typ"], self.header["typ"])
        self.assertEqual(newJwtJson[HEADER]["alg"], self.header["alg"])
        self.assertEqual(newJwtJson[HEADER]["kid"], self.addHeader["kid"])

        self.assertEqual(newJwtJson[PAYLOAD], self.jwtJson[PAYLOAD])
        self.assertEqual(newJwtJson[SIGNATURE], self.jwtJson[SIGNATURE])

    def testChangeAlg(self):
        with self.assertRaises(InvalidJwtJson):
            changeAlg({}, "test")

        newJwtJson = changeAlg(self.jwtJson, "test")
        self.assertEqual(newJwtJson[HEADER]["alg"], "test")

        self.assertEqual(newJwtJson[PAYLOAD], self.jwtJson[PAYLOAD])
        self.assertEqual(newJwtJson[SIGNATURE], self.jwtJson[SIGNATURE])

    def testChangePayload(self):
        with self.assertRaises(InvalidJwtJson):
            changePayload({}, {})

        newJwtJson = changePayload(self.jwtJson, self.addPayload)

        self.assertEqual(newJwtJson[PAYLOAD], self.jwtJson[PAYLOAD])

        self.assertEqual(newJwtJson[HEADER], self.jwtJson[HEADER])
        self.assertEqual(newJwtJson[SIGNATURE], self.jwtJson[SIGNATURE])

    def testSignature(self):
        with self.assertRaises(InvalidJwtJson):
            signature({}, "")

        jwt = signature(self.jwtJson, "")
        self.assertEqual(jwt, self.jwt)

        jwtJson = jwtToJson(self.jwtRsa)
        jwtJson = changeAlg(jwtJson, "HS256")
        jwt = signature(jwtJson, open(self.path).read())
        self.assertEqual(jwt, self.jwtHs256)

        newJwtJson = self.jwtJson
        newJwtJson[HEADER]["alg"] = "unknowAlg"
        with self.assertRaises(UnknownAlg):
            signature(newJwtJson, "")

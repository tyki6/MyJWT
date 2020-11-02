import json
import re
from unittest import TestCase

import requests
import requests_mock
from click.testing import CliRunner

from MyJWT.modifyJWT import changePayload
from MyJWT.utils import jwtToJson, HEADER, PAYLOAD, SIGNATURE
from MyJWT.variables import NOT_VALID_JWT, VALID_PAYLOAD_JSON, NEW_JWT, VALID_SIGNATURE, CHECK_DOCS, NOT_CRAKED, CRACKED
from MyJWT.myjwt_cli import myjwt_cli


class TestMain(TestCase):

    def setUp(self):
        self.jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6ImEifQ.Fjziy6GSQpP9tQRyko5APZjdymkQ8EJGOa" \
                   "-A2JQ6xcAVucXRhZbdBbAM2DG8io_brP_ROAqYaNlvRVsztXoPHFz_e7D2K0q6f02RXeRwZJGOhy0K" \
                   "-Oj9Z1UmFJWqVpAAafN75w7OKoSRh6BtQfH8XDleqwpVoywCuWFdYrSbqBoVskRQkp8H-HUC5XmN5om4" \
                   "-NdiQkiKa7OFQ6Hoklclz9_WD5rc" \
                   "-HWJp3rJW4EIHzOPfs1GuDuhtIRu0uuRYp4vvzLZcVm0BhlK9e_fmFcbsTz3MwVHIeFEIx2NjQdhE" \
                   "-CefQ4tNg6Rr6OtgGExToUfD0i0mAoAhTcvmoyO6c2paQ"
        self.runner = CliRunner()
        self.jwtBruteForce = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ" \
                             ".Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
        self.password = "./wordlist/common_pass.txt"
        self.jwtKid = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ" \
                      ".2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
        self.injection = "../../../../../../dev/null"

    def testErrorCli(self):
        result = self.runner.invoke(myjwt_cli, [])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, ['Peter'])
        self.assertIn(NOT_VALID_JWT, result.output)
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwt])
        self.assertEqual(result.exit_code, 0)

    def testPayload(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--full-payload'])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--full-payload', "test"])
        self.assertIn(VALID_PAYLOAD_JSON, result.output)

        result = self.runner.invoke(myjwt_cli,
                                    [self.jwt, '--full-payload', "{\"username\": \"test\", \"password\": \"test\"}"])
        jwtVerify = changePayload(jwtToJson(self.jwt), json.loads("{\"username\": \"test\", \"password\": \"test\"}"))
        jwt = re.search(NEW_JWT + "(.*)", result.output).groups()[0]
        self.assertEqual(jwtToJson(jwt), jwtVerify)
        self.assertEqual(result.exit_code, 0)

    def testAddHeader(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--add-header'])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--add-header', "admin"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--add-header', "username=admin"])
        jwt = re.search(NEW_JWT + "(.*)", result.output).groups()[0]
        jwtJson = jwtToJson(jwt)
        self.assertEqual(jwtJson[HEADER]["username"], "admin")
        self.assertEqual(result.exit_code, 0)

    def testAddPayload(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--add-payload'])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--add-payload', "admin"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--add-payload', "username=admin"])
        jwt = re.search(NEW_JWT + "(.*)", result.output).groups()[0]
        jwtJson = jwtToJson(jwt)
        self.assertEqual(jwtJson[PAYLOAD]["username"], "admin")
        self.assertEqual(result.exit_code, 0)

    def testSign(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--sign'])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--sign', "test"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwtBruteForce, '--sign', "pentesterlab"])
        jwt = re.search(NEW_JWT + "(.*)", result.output).groups()[0]
        self.assertEqual(self.jwtBruteForce, jwt)
        self.assertEqual(result.exit_code, 0)

    def testVerify(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--verify'])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--verify', "test"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwtBruteForce, '--verify', "pentesterlab"])
        self.assertIn(VALID_SIGNATURE, result.output)
        self.assertEqual(result.exit_code, 0)

    def testNoneVulnerability(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--none-vulnerability'])
        jwt = re.search(NEW_JWT + "(.*)", result.output).groups()[0]
        self.assertEqual("none", jwtToJson(jwt)[HEADER]["alg"])
        self.assertEqual("", jwtToJson(jwt)[SIGNATURE])
        self.assertEqual(result.exit_code, 0)

    def testHmac(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--hmac'])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '--hmac', "./examples/05-rsa-hmac-confusion/public.pem"])
        self.assertEqual(result.exit_code, 0)

    def testBruteForceCli(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, "--bruteforce", "azdzd"])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwt, "--bruteforce", self.password])
        self.assertIn(CHECK_DOCS, result.output)
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwtBruteForce, "--bruteforce", "./wordlist/empty.txt"])
        self.assertIn(NOT_CRAKED, result.output)
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwtBruteForce, "--bruteforce", self.password])
        self.assertIn(CRACKED + "pentesterlab", result.output)
        self.assertEqual(result.exit_code, 0)

    def testKid(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--kid'])
        self.assertEqual(result.exit_code, 2)

        result = self.runner.invoke(myjwt_cli, [self.jwtKid, '--kid', self.injection])
        self.assertEqual(result.exit_code, 0)

    def testPrint(self):
        result = self.runner.invoke(myjwt_cli, [self.jwt, '--print'])
        self.assertEqual(result.exit_code, 0)

    @requests_mock.mock()
    def testUrl(self, m):
        status_code = 200
        m.get("http://localhost:8080", json={}, status_code=status_code)

        result = self.runner.invoke(myjwt_cli,
                                    [self.jwt, '-u', "http://localhost:8080", "-c", "data=data", "-d", "data=data"])
        self.assertEqual(result.exit_code, 0)

        result = self.runner.invoke(myjwt_cli,
                                    [self.jwt, '-u', "http://localhost:8080", "-c", "data"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '-u', "http://localhost:8080", "-d", "data"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '-u', "http://localhost:8080", "-d", "data=MY_JWT"])
        self.assertEqual(result.exit_code, 0)

        result = self.runner.invoke(myjwt_cli, [self.jwt, '-u', "http://localhost:8080", "-c", "data=MY_JWT"])
        self.assertEqual(result.exit_code, 0)

        # m.side_effect = requests.exceptions.ConnectionError()
        # result = self.runner.invoke(myjwt_cli, [self.jwt, '-u', "http://localhost:8080"])
        # self.assertEqual('', result.output)
        # self.assertEqual(result.exit_code, 1)

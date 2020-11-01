from MyJWT.modifyJWT import addpayload, addheader, changePayload
from MyJWT.utils import jwtToJson, SIGNATURE, encodeJwt

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
# header {"typ": "JWT", "alg": "HS256"}
# payload {"user": null}
jwtJson = jwtToJson(jwt)
# "header"  = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"user": null}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"


jwtJson = addpayload(jwtJson, {"username": "admin", "password": "admin"})
# "header" = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"username": "admin", "password": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwtJson = addheader(jwtJson, {"kid": "001"})
# "header" = {"typ": "JWT", "alg": "HS256", "kid": "001"}
# "payload" = {"username": "admin", "password": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwtJson = changePayload(jwtJson, {"username": "admin"})
# "header" = {"typ": "JWT", "alg": "HS256", "kid": "001"}
# "payload" = {"username": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwt = encodeJwt(jwtJson) + "." + jwtJson[SIGNATURE]
print(jwt)


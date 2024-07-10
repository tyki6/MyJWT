from myjwt.modify_jwt import add_header, add_payload, change_payload
from myjwt.utils import SIGNATURE, encode_jwt, jwt_to_json

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
# header {"typ": "JWT", "alg": "HS256"}
# payload {"user": null}
jwt_json = jwt_to_json(jwt)
# "header"  = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"user": null}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"


jwt_json = add_payload(jwt_json, {"username": "admin", "password": "admin"})
# "header" = {"typ": "JWT", "alg": "HS256"}
# "payload" = {"username": "admin", "password": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwt_json = add_header(jwt_json, {"kid": "001"})
# "header" = {"typ": "JWT", "alg": "HS256", "kid": "001"}
# "payload" = {"username": "admin", "password": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwt_json = change_payload(jwt_json, {"username": "admin"})
# "header" = {"typ": "JWT", "alg": "HS256", "kid": "001"}
# "payload" = {"username": "admin"}
# "signature" = "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
jwt = encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE]
print(jwt)

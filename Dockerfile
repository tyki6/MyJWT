FROM bitnami/python:3.8 as builder

WORKDIR /home/app

COPY requirements.txt .
COPY dev-requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

COPY MyJWT MyJWT
COPY wordlist wordlist
COPY setup.py setup.py
COPY README.md README.md
RUN python setup.py install

FROM bitnami/python:3.8

COPY --from=builder /opt/bitnami/python/lib/python3.8/site-packages /opt/bitnami/python/lib/python3.8/site-packages
COPY --from=builder /opt/bitnami/python/bin/myjwt /opt/bitnami/python/bin/myjwt
WORKDIR /home

COPY wordlist wordlist
ENTRYPOINT ["myjwt"]
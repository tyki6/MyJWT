FROM bitnami/python:3.9 as builder
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install --no-install-recommends -y git
WORKDIR /home/app

COPY requirements.txt .
COPY dev-requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

COPY .git .git
# for docs/requirements
COPY docs/ docs/
COPY myjwt myjwt
COPY wordlist wordlist
COPY setup.py setup.py
COPY README.md README.md
ENV PYTHONPATH=${PYTHONPATH}:/home/app/myjwt
RUN python setup.py install

FROM bitnami/python:3.9

COPY --from=builder /opt/bitnami/python/lib/python3.9/site-packages /opt/bitnami/python/lib/python3.9/site-packages
COPY --from=builder /opt/bitnami/python/bin/myjwt /opt/bitnami/python/bin/myjwt
WORKDIR /home

COPY wordlist wordlist
ENTRYPOINT ["myjwt"]

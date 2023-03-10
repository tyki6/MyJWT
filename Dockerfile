FROM bitnami/python:3.11 as base
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

FROM base as poetry
RUN pip install poetry==1.4.0 --no-cache-dir
COPY poetry.lock pyproject.toml /app/
RUN poetry export -o requirements.txt

FROM base as build
COPY --from=poetry /app/requirements.txt /tmp/requirements.txt
RUN python -m venv .venv && \
    .venv/bin/pip install -r /tmp/requirements.txt

FROM base as builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
# hadolint ignore=DL3008
RUN apt-get update  \
&& apt-get install make --no-install-recommends -y  \
&& apt-get clean \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH
ENV PYTHONPATH=${PYTHONPATH}:/app/myjwt
COPY --from=build /app/.venv /app/.venv
COPY .git .git
# for docs/requirements
COPY docs/ docs/
COPY myjwt myjwt
COPY wordlist wordlist
COPY setup.py setup.py
COPY README.md README.md
COPY wordlist wordlist
ENTRYPOINT ["python", "myjwt/myjwt_cli.py"]

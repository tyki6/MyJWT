FROM bitnami/python:3.8

RUN groupadd -g 1001 app && useradd -r -u 1001 -g app app
RUN mkdir /home/app && chown 1001 /home/app
USER 1001
WORKDIR /home/app

ADD requirements.txt .
RUN pip install --upgrade pip && pip install --user -r requirements.txt

ADD MyJWT MyJWT
ADD wordlist wordlist
ADD setup.py setup.py
ADD README.md README.md
RUN python setup.py install
CMD myjwt
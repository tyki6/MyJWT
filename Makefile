.PHONY: docs
tox:
	pip install tox
	tox --recreate
test:
	coverage run -p -m pytest
flake8:
	pip install flake8
	flake8 tests MyJWT examples
deploy:
	pip install setuptools wheel twine
	echo -e "[pypi]" >> ~/.pypirc
	echo -e "username = $PYPI_USERNAME" >> ~/.pypirc
	echo -e "password = $PYPI_PASSWORD" >> ~/.pypirc
	python setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist

fake-deploy:
	pip install setuptools wheel twine
	echo -e "[pypi]" >> ~/.pypirc
	echo -e "username = $PYPI_USERNAME" >> ~/.pypirc
	echo -e "password = $PYPI_PASSWORD" >> ~/.pypirc
	python setup.py sdist
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*
	rm -fr build dist

docker:
	echo "$DOCKER_PASSWORD" | docker login -u $DOCKER_LOGIN --password-stdin docker.pkg.github.com
	docker build -t docker.pkg.github.com/$IMAGE_NAME:$DOCKER_TAG .
	docker push docker.pkg.github.com/$IMAGE_NAME:$DOCKER_TAG
install:
	pip install -r requirements.txt

install-dev:
	pip install -r dev-requirements.txt

full-install: install install-dev

freeze:
	pip-compile --output-file requirements.txt setup.py
help:
	@echo "make help              Show this help message"
	@echo "make test              Run Unit test"
	@echo "make flake8            Run flake8"
	@echo "make deploy            Deploy package on pypi"
	@echo "make fake-deploy       Test Deploy"
	@echo "make full-install      Install requirements + dev requirements"
	@echo "make install           Install requirements"
	@echo "make install-dev       Install dev requirements"
.PHONY: docs
tox:
	pip install tox
	tox --recreate
test:
	coverage run -p -m pytest
flake8:
	flake8 tests MyJWT examples
deploy:
	pip install setuptools wheel twine
	echo -e "[pypi]" >> ~/.pypirc
	echo -e "username = $PYPI_USERNAME" >> ~/.pypirc
	echo -e "password = $PYPI_PASSWORD" >> ~/.pypirc
	python3 setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist

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
	@echo "make flake8            Run the code linter(s) and print any warnings"
	@echo "make deploy            Deploy package on pypi"
	@echo "make publish-dev       Test Deploy"
	@echo "make docs              Create html docs"
	@echo "make install           Install requirements"
	@echo "make install-dev       Install dev requirements"
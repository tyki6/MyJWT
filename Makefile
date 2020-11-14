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
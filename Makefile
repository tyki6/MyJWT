.PHONY: docs
tox:
	pip install tox
	tox --recreate
test:
	coverage run -p -m pytest
flake8:
	flake8 tests MyJWT examples
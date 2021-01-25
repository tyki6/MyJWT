install:
	pip install -r requirements.txt

install-dev:
	pip install -r dev-requirements.txt

install-lint:
	pip install -r lint-requirements.txt

full-install: install install-dev install-lint
	cd docs && pip install -r requirements.txt && cd ..
lint:
	pre-commit run --all-files
tox:
	pip install tox
	tox
docstr:
	docstr-coverage myjwt tests --skipinit --failunder 95
test:
	coverage run --branch -p -m pytest --capture=sys
coverage:
	coverage combine | true && coverage report -m
html:
	cd docs && make html && cd ../
deploy:
	pip install setuptools wheel twine
	echo "[pypi]" >> ~/.pypirc
	echo "username = ${PYPI_USERNAME}" >> ~/.pypirc
	echo "password = ${PYPI_PASSWORD}" >> ~/.pypirc
	python setup.py sdist bdist_wheel
	twine upload dist/*
	rm -fr build dist

fake-deploy:
	pip install setuptools wheel twine
	echo "[pypi]" >> ~/.pypirc
	echo "username = ${PYPI_USERNAME}" >> ~/.pypirc
	echo "password = ${PYPI_PASSWORD}" >> ~/.pypirc
	python setup.py sdist
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*
	rm -fr build dist

docker:
	echo "$DOCKER_PASSWORD" | docker login -u $DOCKER_LOGIN --password-stdin docker.pkg.github.com
	docker build -t docker.pkg.github.com/$IMAGE_NAME:$DOCKER_TAG .
	docker push docker.pkg.github.com/$IMAGE_NAME:$DOCKER_TAG
clean:
	rm -rf docs/build .tox .pytest_cache build circleci myjwt.egg-info dist coverage_html_report *.json *.pem *.crt dumpSyntax .coverage .coverage.* .rnd .mypy_cache
freeze:
	pip freeze > freeze.txt
help:
	@echo "make install           Install requirements."
	@echo "make install-dev       Install dev requirements."
	@echo "make install-lint      Install lint requirements."
	@echo "make full-install      Install requirements + dev requirements + docs requirements."
	@echo "make lint              Run Lint."
	@echo "make docstr            Run docstr report."
	@echo "make tox               Run Unit test tox."
	@echo "make test              Run Unit test."
	@echo "make coverage          Show coverage report."
	@echo "make html              Generate docs."
	@echo "make deploy            Deploy package on pypi."
	@echo "make fake-deploy       Test Deploy."
	@echo "make docker            Build docker and pushblish on github registry."
	@echo "make freeze            Run pip freeze."
	@echo "make clean             Clean Your project.Delete useless file."
	@echo "make help              Show this help message."

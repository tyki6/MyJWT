import setuptools

from MyJWT.variables import VERSION

with open("README.md", "r") as f:
    long_description = f.read()
f.close()

with open('dev-requirements.txt', 'r') as f:
    dev_requires = [line.strip() for line in f]
    f.close()

with open('requirements.txt', 'r') as f:
    install_requires = [line.strip() for line in f]
    f.close()

setuptools.setup(
    name="myjwt",
    version=VERSION,
    author="mBouamama",
    author_email="matthieubouamama@gmail.com",
    description="Pentesting Tool for JWT(JSON Web Tokens).Modify/Crack/Check Your jwt.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mBouamama/MyJWT",
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "myjwt = MyJWT.myjwt_cli:myjwt_cli",
        ],
    },
    extras_require={
        "dev": dev_requires,
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.6",
)

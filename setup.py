import setuptools

from MyJWT.myjwt_cli import VERSION

with open("README.md", "r") as fh:
    long_description = fh.read()
dev_requires = [
    'coverage',
    'flake8',
    'pytest',
]

install_requires = [
    "click",
    "requests"
]

setuptools.setup(
    name="myjwt",
    version=VERSION,
    author="mBouamama",
    author_email="matthieubouamama@gmail.com",
    description="Jwt tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mBouamama/MyJWT",
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'myjwt = MyJWT.myjwt_cli:myjwt_cli',
        ],
    },
    extras_require={
        'dev': dev_requires,
    },
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)

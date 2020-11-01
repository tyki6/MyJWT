import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="MyJWT",
    version="1.0.0",
    author="mBouamama",
    author_email="matthieubouamama@gmail.com",
    description="Jwt tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mBouamama/MyJWT",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
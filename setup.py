# type: ignore
import re

import setuptools

# import subprocess

version = re.search(
    r'^__version__\s*=\s*"(.*)"',
    open("myjwt/__init__.py").read(),
    re.M,
).group(
    1,
)
# for kali linux package i comment this part
# try:
#     commit = subprocess.check_output("git rev-parse --verify HEAD", shell=True)
# except subprocess.CalledProcessError as e:
#     print("Exception on process, rc=", e.returncode, "output=", e.output)
#     commit = b"commit name not found"
#
# with open("myjwt/__init__.py", "w") as f:
#     f.write(
#         f'"""autogenerated"""\n__version__ = "{str(version)}"\n__commit__ = "{str(commit, "utf-8").strip()}"\n',
#     )
# f.close()

with open("README.md") as f:
    long_description = f.read()
f.close()

setuptools.setup(
    name="myjwt",
    version=version,
    author="mBouamama",
    author_email="matthieubouamama@gmail.com",
    description="Pentesting Tool for JWT(JSON Web Tokens).Modify/Crack/Check Your jwt.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mBouamama/MyJWT",
    entry_points={"console_scripts": ["myjwt = myjwt.myjwt_cli:myjwt_cli"]},
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
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.7",
)

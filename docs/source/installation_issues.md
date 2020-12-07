# Installation Issues
If you don't find any issues, send me a github issue.Thanks you.
## Windows
### CryptoGraphy package
- Install OpenSSL by using the installer from here: https://slproweb.com/products/Win32OpenSSL.html
- Open a cmd line terminal and run the following:
- ```set INCLUDE=C:\OpenSSL-Win32\include;%INCLUDE%```
- ```set LIB=C:\OpenSSL-Win32\lib;%LIB%```
- ```pip install cryptography```

 More information [here](https://stackoverflow.com/questions/45089805/pip-install-cryptography-in-windows)

### PyOpenSSL package
More information [here](https://stackoverflow.com/questions/5267092/how-do-i-install-pyopenssl-on-windows-7-64-bit)

### Install Make
Run powershell as admin and run:
```
choco install make
```

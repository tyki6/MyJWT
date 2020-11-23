# Installation
To install myjwt, simply use pip:
```
pip install myjwt
```
To run mywt from a docker image, run:
```
docker run -v $(pwd)/wordlist:/home/app/wordlist/ -it ghcr.io/mBouamama/MyJWT myjwt
```
To install myjwt, on git:
```
git clone https://github.com/mBouamama/MyJWT.git
cd ./MyJWT
pip install -r requirements.txt
python myjwt_cli.py --help
```
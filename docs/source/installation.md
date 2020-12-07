# Installation
To install myjwt, simply use pip:
```
pip install myjwt
```
To run mywt from a docker image, run:
```
docker run -it docker.pkg.github.com/mbouamama/myjwt/myjwt:latest myjwt

# mount volume for wordlist
docker run -v $(pwd)/wordlist:/home/wordlist/  -it docker.pkg.github.com/mbouamama/myjwt/myjwt:latest myjwt
# On Windows
docker run -v %CD%/wordlist:/home/wordlist/  -it docker.pkg.github.com/mbouamama/myjwt/myjwt:latest myjwt
```
To install myjwt, on git:
```
git clone https://github.com/mBouamama/MyJWT.git
cd ./MyJWT
pip install -r requirements.txt
python MyJWT/myjwt_cli.py --help
```

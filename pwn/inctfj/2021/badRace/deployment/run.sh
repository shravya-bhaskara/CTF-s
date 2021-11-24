#!/bin/sh

cd admin
apt-get -qq -y install python2
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
python2 get-pip.py
apt-get -qq -y install python2-dev
pip2 install pwntools
python2 chall.py

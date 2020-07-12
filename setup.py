import os
from setuptools import setup, find_packages
import shutil


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


if not os.path.exists('build'):
    os.mkdir('build')
scripts = (
    ('main.py', 'usbrply'),
    ('serial.py', 'usbrply-serial'),
)
scripts_dist = []
for src_fn, prog_name in scripts:
    # Make script names more executable like
    dst = 'build/' + prog_name
    #shutil.copy(src_fn, dst)
    if os.path.exists(dst):
        os.unlink(dst)
    os.symlink(os.path.realpath(src_fn), dst)
    scripts_dist.append(dst)

setup(
    name="usbrply",
    version="2.0.0",
    author="John McMaster",
    author_email='JohnDMcMaster@gmail.com',
    description=("Replay captured USB packets from .pcap file."),
    license="BSD",
    keywords="libusb pcap",
    url='https://github.com/JohnDMcMaster/usbrply',
    packages=find_packages(),
    scripts=scripts_dist,
    install_requires=[
        "python-pcapng",
    ],
    long_description=read('README.md'),
    classifiers=[
        "License :: OSI Approved :: BSD License",
    ],
)

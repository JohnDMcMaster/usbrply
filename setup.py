import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="usbrply",
    version="2.1.1",
    author="John McMaster",
    author_email='JohnDMcMaster@gmail.com',
    description=("Replay captured USB packets from .pcap file."),
    license="BSD",
    keywords="libusb pcap",
    url='https://github.com/JohnDMcMaster/usbrply',
    packages=find_packages(),
    install_requires=[
        "python-pcapng",
    ],
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    classifiers=[
        "License :: OSI Approved :: BSD License",
    ],
    platforms='any',
    entry_points = {
        'console_scripts': [
            'usbrply=usbrply.main:main'
        ]
    }
)

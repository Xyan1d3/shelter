#!/usr/bin/python3
import setuptools
import subprocess


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

shelter_version = (
    subprocess.run(["git", "describe", "--tags"], stdout=subprocess.PIPE)
    .stdout.decode("utf-8")
    .strip()
)

setuptools.setup(
    name="pwnshelter",
    version=shelter_version,
    author="Bides \'Xyan1d3\' Das",
    author_email="blackviking.soapmactavish@gmail.com",
    description="Reverse Shell Payload Handler",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Xyan1d3/shelter",
    project_urls={
        "Bug Tracker": "https://github.com/Xyan1d3/shelter/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
    ],
    packages=setuptools.find_packages(),
    entry_points={"console_scripts": ["shelter = shelter.shelter:main"]},
    python_requires=">=3.6",
    install_requires=[
        "argparse >= 1.2",
        "pyperclip >= 1.6.0",
        "netifaces >= 0.10.8",
        "requests >= 2.25.1",
    ],
)

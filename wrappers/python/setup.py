"""Module setup."""

import os

from setuptools import find_packages, setup

PACKAGE_NAME = "aries_askar_jamshale"
VERSION = "0.3.3b10"

with open(os.path.abspath("./README.md"), "r") as fh:
    long_description = fh.read()


def parse_requirements(filename: str):
    """Load requirements from a pip requirements file."""
    line_iter = (line.strip() for line in open(filename))
    return [line for line in line_iter if line and not line.startswith("#")]


if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        author="Hyperledger Aries Contributors",
        author_email="aries@lists.hyperledger.org",
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/hyperledger/aries-askar",
        packages=find_packages(),
        install_requires=parse_requirements("requirements.txt"),
        tests_require=parse_requirements("requirements.dev.txt"),
        include_package_data=True,
        package_data={
            "": [
                "aries_askar.dll",
                "libaries_askar.dylib",
                "libaries_askar.so",
            ]
        },
        python_requires=">=3.6.3",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ],
    )

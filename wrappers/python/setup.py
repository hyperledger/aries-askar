"""Module setup."""

import os
import runpy
from setuptools import find_packages, setup

PACKAGE_NAME = "aries_askar"
version_meta = runpy.run_path("./{}/version.py".format(PACKAGE_NAME))
VERSION = version_meta["__version__"]

with open(os.path.abspath("./README.md"), "r") as fh:
    long_description = fh.read()


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

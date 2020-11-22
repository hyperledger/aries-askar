"""Module setup."""

import runpy
from setuptools import find_packages, setup

PACKAGE_NAME = "aries_askar"
version_meta = runpy.run_path("./{}/version.py".format(PACKAGE_NAME))
VERSION = version_meta["__version__"]

if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        author="Hyperledger Aries Contributors",
        author_email="aries@lists.hyperledger.org",
        url="https://github.com/andrewwhitehead/aries-askar",
        packages=find_packages(),
        include_package_data=True,
        package_data={
            "lib": [
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

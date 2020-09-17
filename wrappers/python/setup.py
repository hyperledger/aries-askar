"""Module setup."""

import runpy
from setuptools import find_packages, setup

PACKAGE_NAME = "aries_store"
version_meta = runpy.run_path("./{}/version.py".format(PACKAGE_NAME))
VERSION = version_meta["__version__"]

if __name__ == "__main__":
    setup(
        name=PACKAGE_NAME,
        version=VERSION,
        url="https://github.com/andrewwhitehead/aries-store-kv",
        packages=find_packages(),
        include_package_data=True,
        package_data={
            "indy_vdr": [
                "aries_store_kv.dll",
                "libaries_store_kv.dylib",
                "libaries_store_kv.so",
            ]
        },
        python_requires=">=3.6.3",
        classifiers=[
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: Apache Software License",
            "Operating System :: OS Independent",
        ],
    )

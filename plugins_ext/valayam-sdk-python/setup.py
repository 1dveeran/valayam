from setuptools import setup, find_packages

setup(
    name="valayam-sdk",
    version="0.1.0",
    description="Official Python SDK for writing Valayam Security Plugins",
    author="Valayam Team",
    packages=find_packages(),
    install_requires=[
        "grpcio>=1.59.0",
        "protobuf>=4.24.4",
    ],
)

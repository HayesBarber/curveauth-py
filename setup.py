from setuptools import setup, find_packages

setup(
    name="curveauth",
    version="0.1.0",
    description="ECC signature and key handling",
    author="Hayes Barber",
    packages=find_packages(),
    install_requires=[
        "cryptography>=45.0.4,<46.0.0",
    ],
    python_requires=">=3.7",
)

#!/usr/bin/env python3
"""Setup script for NetSec Toolkit Pro."""

from setuptools import setup, find_packages

setup(
    name="netsec-toolkit-pro",
    version="2.0.0",
    description="A modular network security auditing toolkit",
    author="Hacktor",
    license="MIT",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "jinja2>=2.11.0",
        "pyyaml>=5.4",
    ],
    extras_require={
        "wifi": ["pywifi>=0.3"],
        "sniff": ["scapy>=2.4"],
        "all": ["pywifi>=0.3", "scapy>=2.4", "cryptography>=3.4"],
    },
    entry_points={
        "console_scripts": [
            "netsec=netsec_toolkit.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Security Professionals",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
)

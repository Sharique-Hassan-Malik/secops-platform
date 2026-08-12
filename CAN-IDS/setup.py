from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="can-ids",
    version="1.0.0",
    author="Sharique Hassan Malik",
    description="CAN Bus Intrusion Detection System — anomaly detection on Controller Area Network traffic",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests*"]),
    python_requires=">=3.11",
    install_requires=["rich>=13.0"],
    extras_require={"dev": ["pytest>=7.0", "pytest-cov>=4.0"]},
    entry_points={"console_scripts": ["can-ids=can_ids.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Scientific/Engineering",
    ],
)

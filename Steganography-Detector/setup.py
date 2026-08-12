from setuptools import setup, find_packages

setup(
    name="stegdetect",
    version="1.0.0",
    packages=find_packages(exclude=["tests*", "benchmarks*"]),
    python_requires=">=3.10",
    install_requires=[
        "numpy>=1.24",
        "Pillow>=9.0",
        "scipy>=1.10",
        "soundfile>=0.12",
    ],
    entry_points={
        "console_scripts": [
            "stegdetect=stegdetect.cli:main",
        ],
    },
)

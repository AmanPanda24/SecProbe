from setuptools import setup, find_packages

setup(
    name="secprobe",
    version="1.0.0",
    author="Aman Kumar Panda",
    description="AI-assisted web security misconfiguration scanner",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "flask>=3.0.0",
        "flask-cors>=4.0.0",
        "colorama>=0.4.6",
        "python-nmap>=0.7.1",
        "cryptography>=42.0.0",
        "tabulate>=0.9.0",
        "click>=8.1.7",
        "pyOpenSSL>=24.0.0",
        "gunicorn>=21.2.0",
    ],
    entry_points={
        "console_scripts": [
            "secprobe=secprobe.cli:main",
        ],
    },
    python_requires=">=3.9",
)

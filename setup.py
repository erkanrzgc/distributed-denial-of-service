from setuptools import setup, find_packages

setup(
    name="ddos-toolkit",
    version="1.0.0",
    packages=find_packages(),
    py_modules=["cli"],
    include_package_data=True,
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "ddos=cli:cli",
        ],
    },
    install_requires=[
        "textual>=0.52.0",
        "rich>=13.7.0",
        "click>=8.1.0",
        "aiohttp>=3.9.0",
        "scapy>=2.5.0",
        "pydantic>=2.5.0",
        "pydantic-settings>=2.1.0",
        "pyyaml>=6.0",
        "structlog>=24.1.0",
        "uvloop>=0.19.0",
        "python-dateutil>=2.8.0",
        "orjson>=3.9.0",
    ],
)

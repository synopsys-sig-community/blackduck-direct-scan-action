import setuptools
import platform
from bdscan import globals

platform_system = platform.system()

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="blackduck-direct-scan-action",
    version=globals.scan_utility_version,
    author="Matthew Brady",
    author_email="mbrad@synopsys.com",
    description="Backend Python program to support CI integrations using wrappers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/matthewb66/blackduck-direct-scan-action",
    packages=setuptools.find_packages(),
    install_requires=[
        'blackduck>=1.0.4',
        "pyGitHub",
        "aiohttp",
        "networkx",
        "requests",
        "semver",
        "lxml",
        "azure-devops==6.0.0b4",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': ['blackduck-direct-scan-action=bdscan.bdscanaction:main'],
    },
)

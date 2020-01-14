import os
import json
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), 'ievv_auth', 'version.json')) as f:
    version = json.loads(f.read())

setup(
    name='ievv_auth',
    description='The ievv_auth django project.',
    version=version,
    author='ievv',
    packages=find_packages(exclude=['manage']),
    install_requires=[
        'Django>=1.11',
        'PyJWT>=1.7.1'
    ],
    include_package_data=True,
    zip_safe=False,
)

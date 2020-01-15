import os
import json
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), 'ievv_auth', 'version.json')) as f:
    version = json.loads(f.read())


setup(
    name='ievv-auth',
    description='Authentication modules for the Django framework.',
    version=version,
    author='Appresso developers',
    author_email='post@appresso.no',
    packages=find_packages(exclude=['manage']),
    license='BSD',
    install_requires=[
        'Django',
        'PyJWT>=1.7.1',
        'djangorestframework',
        'psycopg2'
    ],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        'Development Status :: 1 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'Operating System :: OS Independent',
        'Programming Language :: Python'
    ]
)

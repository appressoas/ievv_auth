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
    url="https://github.com/appressoas/ievv_auth",
    install_requires=[
        'Django>=3',
        'PyJWT>=1.7.1',
        'djangorestframework',
        'psycopg2',
        'django-ipware'
    ],
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'Operating System :: OS Independent',
        'Programming Language :: Python'
    ]
)

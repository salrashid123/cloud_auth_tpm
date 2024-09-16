import setuptools
import io
import os


package_root = os.path.abspath(os.path.dirname(__file__))

readme_filename = os.path.join(package_root, 'README.md')
with io.open(readme_filename, encoding='utf-8') as readme_file:
    readme = readme_file.read()


setuptools.setup(
    name="cloud_auth_tpm",
    version="0.6.0",
    author="Sal Rashid",
    author_email="salrashid123@gmail.com",
    description="Python TPM based Credentials for Cloud Providers",
    long_description=readme,
    long_description_content_type='text/markdown',
    url="https://github.com/salrashid123/cloud-auth-tpm",
    install_requires=[
          'tpm2_pytss>=2.3.0',
          'cryptography',
          'requests'
    ],
    extras_require={
        'gcp': ['google-auth>=2.34.0'],
        'aws': ['boto3', 'botocore'],
        'azure': ['azure-identity', 'azure-core'],        
    },    
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',

        "Programming Language :: Python",
        "Programming Language :: Python :: 3.0",

        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)

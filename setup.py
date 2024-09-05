import setuptools
import io
import os


package_root = os.path.abspath(os.path.dirname(__file__))

readme_filename = os.path.join(package_root, 'README.md')
with io.open(readme_filename, encoding='utf-8') as readme_file:
    readme = readme_file.read()


setuptools.setup(
    name="google_auth_tpm",
    version="0.0.34",
    author="Sal Rashid",
    author_email="salrashid123@gmail.com",
    description="Python TPM based Credentials for Google Cloud Platform",
    long_description=readme,
    long_description_content_type='text/markdown',
    url="https://github.com/salrashid123/google-auth-library-python-tpm",
    install_requires=[
          'google-auth>=2.34.0',
          'tpm2_pytss>=2.3.0'
    ],
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

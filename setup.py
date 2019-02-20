from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(name='cloudgenix_idname',
      version='1.2.1',
      description='ID -> Name translator for the CloudGenix Python SDK',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/ebob9/cloudgenix-idname',
      author='Aaron Edwards',
      author_email='cloudgenix_idname@ebob9.com',
      license='MIT',
      install_requires=[
            'cloudgenix >= 5.1.1b1'
      ],
      packages=['cloudgenix_idname'],
      classifiers=[
            "Development Status :: 5 - Production/Stable",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 2.7",
            "Programming Language :: Python :: 3"
      ]
      )

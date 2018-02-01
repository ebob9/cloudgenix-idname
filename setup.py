from setuptools import setup

setup(name='cloudgenix_idname',
      version='1.1.1',
      description='ID -> Name translator for the CloudGenix Python SDK',
      url='https://github.com/ebob9/cloudgenix-idname',
      author='Aaron Edwards',
      author_email='cloudgenix_idname@ebob9.com',
      license='MIT',
      install_requires=[
            'cloudgenix >= 4.5.5b3'
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
"""Setup."""

try:
    from setuptools import setup
except:  # pylint: disable=bare-except # noqa: E722 # NOLINT
    from distutils.core import setup  # pylint: disable=wrong-import-order

with open('README.md') as f:
    long_description = f.read()  # pylint: disable=invalid-name

setup(
    author='Soar Technology, Inc.',
    name='statick-fortify',
    description='Statick extension to integrate Fortify.',
    version='0.1.0',
    packages=['statick_tool.plugins.tool'],
    package_data={'statick_tool': ['plugins/tool/*']},
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=['statick'],
    url='https://github.com/soartech/statick-fortify',
    classifiers=[
        "License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Testing",
    ],
)

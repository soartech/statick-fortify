"""Setup."""

try:
    from setuptools import setup
except:  # pylint: disable=bare-except # noqa: E722 # NOLINT
    from distutils.core import setup  # pylint: disable=wrong-import-order

with open('README.md') as f:
    long_description = f.read()  # pylint: disable=invalid-name

TEST_DEPS = [
    'pytest',
    'mock',
]
EXTRAS = {
    'test': TEST_DEPS,
}

VERSION = '0.1.4'

setup(
    author='Soar Technology, Inc.',
    name='statick-fortify',
    description='Statick extension to integrate Fortify.',
    version=VERSION,
    packages=['statick_tool', 'statick_tool.plugins.tool.fortify_plugin'],
    package_dir={'statick_tool.plugins.tool.fortify_plugin': 'fortify_plugin',
                 'statick_tool': '.'},
    package_data={'statick_tool.plugins.tool.fortify_plugin': ['*.yapsy-plugin'],
                  'statick_tool': ['rsc/plugin_mapping/*']},
    long_description=long_description,
    long_description_content_type='text/markdown',
    install_requires=['statick'],
    tests_require=TEST_DEPS,
    extras_require=EXTRAS,
    url='https://github.com/soartech/statick-fortify',
    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Software Development :: Testing",
    ],
)

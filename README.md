# Statick Fortify SCA Plugin

| Service | Status |
| ------- | ------ |
| Build   | [![Travis-CI](https://api.travis-ci.org/soartech/statick-fortify.svg?branch=master)](https://travis-ci.org/soartech/statick-fortify/branches) |
| PyPI    | [![PyPI version](https://badge.fury.io/py/statick-fortify.svg)](https://badge.fury.io/py/statick-fortify) |
| Codecov | [![Codecov](https://codecov.io/gh/soartech/statick-fortify/branch/master/graphs/badge.svg)](https://codecov.io/gh/soartech/statick-fortify) |
| Requirements| [![Requirements Status](https://requires.io/github/soartech/statick-fortify/requirements.svg?branch=master)](https://requires.io/github/soartech/statick-fortify/requirements/?branch=master) |


Statick-Fortify is a plugin to Statick to integrate with [Micro Focus Fortify SCA](https://www.microfocus.com/en-us/products/application-security-testing/overview)
You must have a licensed copy of Micro Focus Fortify SCA in order to use this plugin.

## Additions to Statick
This plugin introduces a new tool plugin to Statick.
The plugin should be automatically detected the next time you run Statick.

## Tested Versions
Statick-Fortify has only been tested with Fortify 18.20.
Other versions may work, but they have not been tested.

## Use Cases
Statick-Fortify currently supports analysis of Maven projects.

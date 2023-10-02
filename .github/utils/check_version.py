import os
import sys
from importlib.util import find_spec

from setuptools.config.expand import StaticModule


package = 'flask_multipass'
sys.path.insert(0, os.getcwd())
version = StaticModule(package, find_spec(package)).__version__
tag_version = sys.argv[1]

if tag_version != version:
    print(f'::error::Tag version {tag_version} does not match package version {version}')
    sys.exit(1)

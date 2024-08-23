import sys
import tomllib
from pathlib import Path


data = tomllib.loads(Path('pyproject.toml').read_text())
version = data['project']['version']
tag_version = sys.argv[1]

if tag_version != version:
    print(f'::error::Tag version {tag_version} does not match package version {version}')
    sys.exit(1)

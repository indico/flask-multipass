import sys
from pathlib import Path

import tomllib

data = tomllib.loads(Path('pyproject.toml').read_text())
version = data['project']['version']
tag_version = sys.argv[1]

if tag_version != version:
    print(f'::error::Tag version {tag_version} does not match package version {version}')
    sys.exit(1)

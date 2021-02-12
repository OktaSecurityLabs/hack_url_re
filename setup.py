import setuptools
import glob
import os.path as osp
import json as _json
from pathlib import Path as _Path

# NOTE:
# - The versions are not strict requirements but these are the versions as tested.
# - 'z3-solver' will be added later if not installed already
requirements = ['ply==3.11', 'toolz==0.9.0']

# If you installed z3 outside of pip, pip won't see it.
# Therefore import it to see if it is installed.
try:
    import z3
except ImportError:
    requirements += ['z3-solver==4.8.10.0']

_package_info = (
    _json.loads(_Path(__file__).parent.joinpath('hack_url_re', 'package_info.json').read_text()))

setuptools.setup(
    name='hack_url_re',
    version=_package_info['version'],
    description='Finds vulns in URL regexes that identify websites',
    author='Andrew Lee',
    license='Apache',
    classifiers=[
        'Programming Language :: Python :: 3.6',
    ],

    install_requires=requirements,

    entry_points={
        'console_scripts': ['hack_url_re=hack_url_re.ui:main',
                            'hack_url_re_batch=hack_url_re.batch_processing:main' ],
    },

    packages=setuptools.find_packages(exclude=[
        'contrib', 'docs', 'tests*', 'scratch',
        'var', 'archive', 'examples'])
)

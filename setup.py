from setuptools import setup, find_packages

setup(
    name="microstack_init",
    description="Optionally interactive init script for Microstack.",
    packages=find_packages(exclude=("tests",)),
    version="0.0.1",
    entry_points={
        'console_scripts': [
            'microstack_init = microstack_init.main:init',
            'set_network_info = microstack_init.main:set_network_info',
        ],
    },
)

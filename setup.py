from setuptools import setup, find_packages

setup(
    name='rpr_oauth',
    use_scm_version=True,
    setup_requires=['setuptools-scm'],
    packages=find_packages(),
    install_requires=[
        'Flask',
        'requests'
    ],
)
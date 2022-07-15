from setuptools import setup

setup(
    name='tlspuffin-analyzer',
    version='0.1',
    packages=['tlspuffin_analyzer'],
    url='',
    license='',
    author='max',
    author_email='max@maxammann.org',
    description='',
    scripts=['tlspuffin-analyzer'],
    install_requires=[
        'jsonslicer',
        'matplotlib',
        'numpy',
        'dateparser',
        'dict-to-dataclass==0.0.8'
    ],
)

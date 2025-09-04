from setuptools import setup
import os

def get_version():
    version_file = os.path.join(os.path.dirname(__file__), 'nr7101', 'version.py')
    with open(version_file, 'r') as f:
        content = f.read()
    namespace = {}
    exec(content, namespace)
    return namespace['__version__']

setup(
    name="nr7101",
    version=get_version(),
    description="Zyxel NR7101 tool",
    author="Pekka Korpinen",
    author_email="pekka.korpinen@iki.fi",
    license="MIT",
    url="https://github.com/pkorpine/nr7101",
    packages=["nr7101"],
    install_requires=[
        "requests>=2.25.0",
        "pycryptodome>=3.15.0"
    ],
    entry_points={
        "console_scripts": ["nr7101-tool=cli:cli"],
    },
)

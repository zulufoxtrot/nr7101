from setuptools import setup

setup(
    name="nr7101",
    version="1.4.2",
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

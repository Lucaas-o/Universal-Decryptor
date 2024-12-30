from setuptools import setup

setup(
    name="message_encryption_tool",
    version="1.0",
    py_modules=["main"],
    install_requires=[
        "pyperclip",
    ],
    entry_points={
        "console_scripts": [
            "encryptor-tool=main:main",
        ],
    },
)

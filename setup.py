from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="flask-rpr-oauth",
    version="1.0.0",
    author="Roleplay Reality",
    author_email="support@roleplayreality.nl",
    description="Flask OAuth 2.0 / OpenID Connect extensie voor Roleplay Reality Auth Server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rpr-development/flask-rpr-oauth",
    packages=find_packages(),
    license="Proprietary",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Framework :: Flask",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Flask>=2.0.0",
        "Authlib>=1.0.0",
        "requests>=2.28.0",
    ],
    extras_require={
        "redis": [
            "redis>=4.0.0",
            "Flask-Session>=0.5.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.990",
        ],
    },
)

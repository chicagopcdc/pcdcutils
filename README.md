# pcdcutils (PCDC Utils)

Handy cross-service tools for PCDC projects

## Set up env
- `python -m venv env`
- `source env/bin/activate`
- `poetry install`

## Usage
Poetry dependency import (pyproject.toml)

`pcdcutils = {git = "https://github.com/chicagopcdc/pcdcutils.git", branch = "master"}`

## Local Tests
- `pytest tests/test_utils.py`

## Using Poetry for setting up env
- `poetry shell`
- `poetry install`
- `poetry update pcdcutils`

## Local Tests with Poetry
- `poetry run pytest tests/test_utils.py`
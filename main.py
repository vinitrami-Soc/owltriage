#!/usr/bin/env python3
"""Run owltriage from a source checkout without installing it: `python main.py hunt --demo`.

After `pip install .` use the `owltriage` command instead.
"""
import sys

from owltriage.cli import main

if __name__ == "__main__":
    sys.exit(main())

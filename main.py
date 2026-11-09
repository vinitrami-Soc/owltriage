#!/usr/bin/env python3
"""Run bluetriage from a source checkout without installing it: `python main.py hunt --demo`.

After `pip install .` use the `bluetriage` command instead.
"""
import sys

from bluetriage.cli import main

if __name__ == "__main__":
    sys.exit(main())

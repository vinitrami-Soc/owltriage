"""`python -m owltriage ...` works the same as the `owltriage` command."""
import sys

from .cli import main

sys.exit(main())

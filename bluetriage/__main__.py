"""`python -m bluetriage ...` works the same as the `bluetriage` command."""
import sys

from .cli import main

sys.exit(main())

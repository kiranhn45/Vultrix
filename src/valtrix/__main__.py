"""Allow `python -m valtrix` as an alternative to the `valtrix` command."""

import sys

from valtrix.cli import main

if __name__ == "__main__":
    sys.exit(main())

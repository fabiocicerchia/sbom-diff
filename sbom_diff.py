#!/usr/bin/env python3
"""sbom-diff entry point. The tool itself lives in the sbom_diff_lib package."""

import sys

from sbom_diff_lib.cli import main

if __name__ == "__main__":
    sys.exit(main())

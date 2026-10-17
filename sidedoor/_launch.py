"""Run sidedoor from a source checkout without installing (used by the demo fake agent)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sidedoor.cli import main  # noqa: E402

sys.exit(main())

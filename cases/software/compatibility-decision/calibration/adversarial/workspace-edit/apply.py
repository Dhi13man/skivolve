from pathlib import Path
import sys


Path(sys.argv[1], "unauthorized.txt").write_text("mutation\n", encoding="utf-8")

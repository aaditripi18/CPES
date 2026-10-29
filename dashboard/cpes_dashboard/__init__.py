"""CPES research dashboard: HTTP API and storage around the unchanged ``cpes`` package.

Nothing in this package scores, detects or evaluates on its own. Detection runs
call ``cpes.orchestration.CpesPipeline``; research experiments run the scripts in
``analysis/`` unchanged and record their output.
"""

__version__ = "0.2.0"

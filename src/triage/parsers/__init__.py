"""Log parsers: raw log lines -> normalised events.

Each parser is resilient: malformed or unrecognised lines are skipped (or marked
``other``), never fatal. Parsers do not filter by time window or source IP; the
detectors do that, using the per-case window recorded in docs/lab_journal.md.
"""

"""Time bounds shared by the route receipt reader and acceptance verifier."""

from datetime import timedelta

MAX_AGE = timedelta(minutes=3)
CLOCK_TOLERANCE = timedelta(seconds=30)

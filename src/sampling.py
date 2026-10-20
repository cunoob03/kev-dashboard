"""Shared source-row sampling for console and CSV verification."""

import random

from . import config


def sample_positions(records):
    """Pick distinct row positions; retain duplicate IDs as separate source rows."""
    size = min(config.VERIFICATION_SAMPLE_SIZE, len(records))
    generator = random.Random(config.VERIFICATION_SEED)
    return generator.sample(range(len(records)), size)

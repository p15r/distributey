import logging
from dy_logging import logger


def test_distributey_logging():
    assert isinstance(logger, logging.RootLogger)
    assert logger.level == logging.INFO
    assert isinstance(logger.handlers[0], logging.StreamHandler)

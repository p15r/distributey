from hyok_logging import logger
import logging


def test_hyok_logging():
    assert isinstance(logger, logging.RootLogger)
    assert logger.level == logging.INFO
    assert isinstance(logger.handlers[0], logging.StreamHandler)

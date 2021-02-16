import logging
import dy_logging


def test_distributey_logging():
    assert isinstance(dy_logging.logger, logging.RootLogger)
    assert dy_logging.logger.level == logging.INFO
    assert isinstance(dy_logging.logger.handlers[0], logging.StreamHandler)

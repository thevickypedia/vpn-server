"""Loads a default logger with StreamHandler set to DEBUG mode.

>>> LOGGER

"""

import logging

LOGGER = logging.getLogger(__name__)
HANDLER = logging.StreamHandler()
HANDLER.setFormatter(
    fmt=logging.Formatter(
        fmt='%(asctime)s - %(levelname)s - [%(module)s:%(lineno)d] - %(funcName)s - %(message)s',
        datefmt='%b-%d-%Y %I:%M:%S %p'
    )
)
LOGGER.addHandler(hdlr=HANDLER)
LOGGER.setLevel(level=logging.DEBUG)

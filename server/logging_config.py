import logging


def setup_logging():
    """
    Set up the logging configuration for the entire project.
    """
    logging.basicConfig(
        level=logging.DEBUG,  #
        format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s - %(lineno)d - %(message)s',
    )

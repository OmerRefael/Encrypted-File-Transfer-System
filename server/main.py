"""
This is the main file of the server application. It initializes and starts the server,
allowing clients to transfer encrypted files for storage.

The server receives requests through a protocol that we have implemented, processes these
requests, and sends responses back to the clients. Additionally, the server is responsible
for storing information about the clients and the files that clients send.

@author: Omer Refael
@data: 20/10/2024
"""

import logging
import logging_config
from server import Server
from utils.file_utils import get_port_from_file


PORT_FILE = "port.info"


def main():
    logging_config.setup_logging()
    logger = logging.getLogger(__name__)

    try:
        port = get_port_from_file(PORT_FILE)
        server = Server(port)
        server.start_server()
    except Exception as e:
        logger.error(e)


if __name__ == '__main__':
    main()

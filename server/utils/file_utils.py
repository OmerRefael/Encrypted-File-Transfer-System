import logging
import os


DEFAULT_PORT = 1256  # Default port number

logger = logging.getLogger(__name__)


def get_port_from_file(file_path: str) -> int:
    """
    Get the port number from the port.info file.
    This function will return the default port number according:
    1. If the file does not exist.
    2. If the file is not opened successfully.
    3. If the file not contains the port number.

    Args:
        file_path (str): The path to the file that contains the port number.

    Returns:
        int: The port number that is read from the file, or the default port number
    """
    try:
        with open(file_path, "r") as file:
            port = file.read().strip()
            if port is None:
                return DEFAULT_PORT
            return int(port)
    except FileNotFoundError:
        logger.warning(f"The file: port.info does not exist. Using the default port number:"
                       f" {DEFAULT_PORT}")
        return DEFAULT_PORT


def store_file(client_name: str, file_name: str, content: bytes, is_first_packet: bool) -> str:
    """
    Store the file content in the client's directory.

    Args:
        client_name (str): The client
        file_name (str): The file name.
        content (bytes): The file content.
        is_first_packet (bool): A flag indicating if this is the first packet of the file.

    Returns:
        str: The path to the stored file.
    """

    try:
        # Get the absolute path to the server folder
        server_directory = os.path.dirname(os.path.abspath(__file__))
        client_dir = os.path.join(server_directory, "clients_files", client_name)

        # Create the client's directory if it doesn't exist
        os.makedirs(client_dir, exist_ok=True)

        # Define the full file path
        file_path = os.path.join(client_dir, file_name)

        # Write the content to the file
        if is_first_packet:
            with open(file_path, "wb") as file:
                file.write(content)
        else:
            with open(file_path, "ab") as file:
                file.write(content)
        return file_path
    except ...:
        raise Exception(f"An error occurred while storing the file {file_name} for the client "
                        f" {client_name}.")

import re
from typing import Dict, Tuple, Any


def is_valid_client_name(client_name: str) -> bool:
    """
    Check if the client name is valid.

    The client name must:
    - Be a string.
    - Contain only letters, numbers, and spaces.
    - Start with a letter.

    Args:
        client_name (str): The client name to check.

    Returns:
        bool: True if the client name is valid, False otherwise.
    """
    return isinstance(client_name, str) and re.match(r'^[A-Za-z][\w\s]*$', client_name)


def check_arguments_types(arguments_types: Dict[str, Tuple[Any, Tuple[type]]], line: int,
                          file: str) -> None:
    """
    Check the types of the arguments.

    Args:
        arguments_types (Dict[str, Tuple[Any, Tuple[type]]): A dictionary where the key is the
        argument name and the value is a tuple containing the argument value and the expected types.
        line (int): The line number in the file where the check is performed.
        file (str): The file name where the check is performed.

    Raises:
        TypeError: If the type of the argument is incorrect.
    """

    for arg_name, (arg_value, arg_types) in arguments_types.items():
        if not isinstance(arg_value, arg_types):
            raise TypeError(f"In file {file}, line {line}: The type of the argument '{arg_name}' "
                            f"is incorrect. Expected types: {arg_types}, Received type: "
                            f" {type(arg_value).__name__}")

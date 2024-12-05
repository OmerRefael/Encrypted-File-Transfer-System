import logging
import os
import inspect
from protocol import (RequestHeader, RequestPayload, ResponseHeader, ResponsePayload, RequestCode,
                      ResponseCode, ResponsePayloadSize)
from database import Database, ClientTable, FileTable
from checksum import calculate_file_checksum
from utils.encryption_utils import encrypt_by_public_key, decrypt_by_aes_key, generate_aes_key
from utils.validation_utils import is_valid_client_name, check_arguments_types
from utils.file_utils import store_file
from utils.general_utils import generate_client_id


LAST_PACKET_TRACKER = {}  # A dictionary to track the last packet number for each client

FILE_NAME = os.path.basename(__file__)
logger = logging.getLogger(__name__)


def get_response(request_header: RequestHeader, request_payload: RequestPayload,
                 database: Database) -> (ResponseHeader, ResponsePayload):
    """
    This function receives a request from a client, processes it, and returns a response.

    Args:
        request_header (RequestHeader): The header of the request.
        request_payload (RequestPayload): The payload of the request.
        database (Database): The database object.

    Returns:
        Tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and
        payload of the response.

    """

    # Check arguments types
    try:
        validate_arguments(request_header, request_payload, database)

        # Update the last seen time of the client
        # (if the client is not correct, or still not exist, nothing will be change)
        database.client_table.update_last_seen(request_header.client_id)

        unpack_methods = {
            RequestCode.REGISTRATION: handle_register_client_request,
            RequestCode.SEND_PUBLIC_KEY: handle_send_public_key_request,
            RequestCode.RECONNECT: handle_reconnect_request,
            RequestCode.SEND_FILE: handle_send_file_request,
            RequestCode.VALID_CRC: handle_valid_crc_request,
            RequestCode.INVALID_CRC: handle_invalid_crc_request,
            RequestCode.INVALID_CRC_IN_THE_FOURTH_TIME:
                handle_invalid_crc_in_the_fourth_time_request
        }

        # Call the appropriate unpacking method
        func = unpack_methods.get(request_header.code)
        if func is None:
            logger.error("The request code is not valid")
            return general_error_response()

        response = func(request_header, request_payload, database)
        return response
    except Exception as e:
        logger.error(e)
        return general_error_response()


def handle_register_client_request(_request_header: RequestHeader, request_payload: RequestPayload,
                                   database: Database) -> (ResponseHeader, ResponsePayload):
    """
    Handle a request to register a new client.

    Args:
        _request_header (RequestHeader): The header of the request.
        request_payload (RequestPayload): The payload of the request.
        database (Database): The database to store client information.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.
    """

    logger.info("register client request received")

    client_table = database.client_table

    validate_fields_in_payload_content(request_payload.payload_content, ["name"])
    client_name = request_payload.payload_content["name"]

    client_id = generate_client_id(client_table.get_list_of_clients())

    if is_registration_valid(client_name, client_table):
        client_table.insert_client(client_id, client_name, None, None)
        response = handle_successful_registration(client_id)
        logger.info("Sending successful registration response")
    else:
        response = handle_failed_registration()
        logger.warning(f"The registration failed with the client name {client_name}")
        logger.info("Sending failed registration response")

    return response


def handle_reconnect_request(request_header: RequestHeader, request_payload: RequestPayload,
                             database: Database) -> (ResponseHeader, ResponsePayload):
    """
    Handle a request to reconnect a client.

    Args:
        request_header (RequestHeader): The header of the request containing client information.
        request_payload (RequestPayload): The payload containing the client name.
        database (Database): The database to update client information.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.
    """

    logger.info("reconnect request received")

    validate_fields_in_payload_content(request_payload.payload_content, ["name"])

    client_id = request_header.client_id
    name = request_payload.payload_content["name"]

    if is_reconnect_accepted(client_id, name, database.client_table):
        response = handle_accepted_reconnect(client_id, database.client_table)
        logger.info("Sending accepted reconnect response")
    else:
        response = handle_rejected_reconnect(client_id)
        logger.warning("The reconnection request is rejected")
        logger.info("Sending rejected reconnect response")
    return response


def handle_send_public_key_request(request_header: RequestHeader, request_payload: RequestPayload,
                                   database: Database) -> (ResponseHeader, ResponsePayload):
    """
   Handle a request to send a public key from a client.

   Args:
       request_header (RequestHeader): The header of the request containing client information.
       request_payload (RequestPayload): The payload containing the public key.
       database (Database): The database to update client information.

   Returns:
       tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.

   Raises:
       ValueError: If the client ID is invalid or if the public key is missing.
   """

    logger.info("public key request received")

    client_table = database.client_table

    # Validate the client ID and the fields in the payload content
    validate_client_id(request_header.client_id, client_table)
    validate_fields_in_payload_content(request_payload.payload_content, ["public_key"])

    # Get the public key from the payload content
    client_id = request_header.client_id
    public_key = request_payload.payload_content["public_key"]

    aes_key = generate_aes_key()

    # Update the client information in the database
    client_table.update_client_public_key(client_id, public_key)
    client_table.update_client_aes_key(client_id, aes_key)

    # Encrypt the AES key with the public key
    aes_key_encrypted = encrypt_by_public_key(public_key, aes_key)

    # Construct the response
    code = ResponseCode.RECEIVED_PUBLIC_KEY_AND_SEND_ENCRYPTED_AES_KEY
    length = ResponsePayloadSize.SEND_ENCRYPTED_AES_KEY_BASIC_SIZE.value + len(aes_key_encrypted)
    payload_content = {
        "client_id": client_id,
        "encrypted_symmetric_key": aes_key_encrypted
    }

    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, length)
    response_payload = ResponsePayload(payload_content, code, length)

    logger.info("Sending AES key encrypted response")
    return response_header, response_payload


def handle_send_file_request(request_header: RequestHeader, request_payload: RequestPayload,
                             database: Database) -> (ResponseHeader, ResponsePayload):
    """
    Handle a request to send a file from a client.

    Args:
        request_header (RequestHeader): The header of the request containing client information.
        request_payload (RequestPayload): The payload containing the file information.
        database (Database): The database to store the file.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.
        or None, None: If the file is not fully received yet.
    """

    # Get the client ID and the file information
    client_id = request_header.client_id
    validate_client_id(client_id, database.client_table)

    fields_of_payload_content = ["file_name", "encrypted_content", "content_size",
                                 "packet_number", "total_packets"]
    validate_fields_in_payload_content(request_payload.payload_content, fields_of_payload_content)

    file_name = request_payload.payload_content["file_name"]
    file_content_encrypted = request_payload.payload_content["encrypted_content"]
    content_size = request_payload.payload_content["content_size"]
    client_name = database.client_table.get_name_according_to_client_id(client_id)

    aes_key = database.client_table.get_aes_key_according_to_client_id(client_id)
    if aes_key is None:
        raise ValueError("The AES key is missing - cannot decrypt the file")

    file_content = decrypt_by_aes_key(aes_key, file_content_encrypted)

    if client_id not in LAST_PACKET_TRACKER:
        LAST_PACKET_TRACKER[client_id] = 0  # Initialize for the client
        logger.info("File request received")

    # Save the file in the adjusted folder of the server
    is_first_packet = request_payload.payload_content["packet_number"] == 1
    path = store_file(client_name, file_name, file_content, is_first_packet)

    # Check the order of the packets
    validate_the_order_of_packets(client_id, request_payload.payload_content["packet_number"])

    # Insert the file into the database
    if (request_payload.payload_content["packet_number"] ==
            request_payload.payload_content["total_packets"]):
        logger.info("Sending file received response")
        return get_file_received_response(client_id, file_name, content_size, path,
                                          database.file_table)

    LAST_PACKET_TRACKER[client_id] += 1  # Update for the client
    return None, None


def handle_valid_crc_request(request_header: RequestHeader, request_payload: RequestPayload,
                             database: Database) -> (ResponseHeader, ResponsePayload):
    """
    Handle a request with a valid CRC.
    
    Args:
        request_header (RequestHeader): The header of the request containing client information.
        request_payload (RequestPayload): The payload containing the file name.
        database (Database): The database to update file information.
    
    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.
    """

    logger.info("valid crc request received")

    validate_client_id(request_header.client_id, database.client_table)
    client_id = request_header.client_id

    validate_fields_in_payload_content(request_payload.payload_content, ["file_name"])
    file_name = request_payload.payload_content["file_name"]

    validate_file_of_client_exists(client_id, file_name, database.file_table)
    database.file_table.set_file_as_verified(client_id, file_name)

    code = ResponseCode.ACCEPT_MESSAGE
    payload_size = ResponsePayloadSize.ACCEPT_MESSAGE_SIZE.value

    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, payload_size)
    response_payload = ResponsePayload({"client_id": client_id}, code, payload_size)

    logger.info("Sending accept message response")

    return response_header, response_payload


def handle_invalid_crc_request(request_header: RequestHeader, request_payload: RequestPayload,
                               database: Database) -> (ResponseHeader, ResponsePayload):
    """
    Handle a request with an invalid CRC.

    Args:
        request_header (RequestHeader): The header of the request containing client information.
        request_payload (RequestPayload): The payload containing the file name.
        database (Database): The database to update file information.

    Returns:
        None, None: No response is need sent back to the client.
    """

    logger.info("invalid crc request received")

    validate_client_id(request_header.client_id, database.client_table)
    client_id = request_header.client_id

    validate_fields_in_payload_content(request_payload.payload_content, ["file_name"])
    file_name = request_payload.payload_content["file_name"]

    validate_file_of_client_exists(client_id, file_name, database.file_table)

    return None, None


def handle_invalid_crc_in_the_fourth_time_request(
    request_header: RequestHeader,
    _request_payload: RequestPayload,
    _database: Database) \
        -> (ResponseHeader, ResponsePayload):
    """
    Handle a request with an invalid CRC in the fourth time.

    Args:
        request_header (RequestHeader): The header of the request containing client information.
        _request_payload (RequestPayload): The payload of the request.
        _database (Database): The database to update file information.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.
    """

    logger.info("invalid crc in the fourth time request received")

    validate_client_id(request_header.client_id, _database.client_table)
    client_id = request_header.client_id

    validate_fields_in_payload_content(_request_payload.payload_content, ["file_name"])
    file_name = _request_payload.payload_content["file_name"]

    validate_file_of_client_exists(client_id, file_name, _database.file_table)

    code = ResponseCode.ACCEPT_MESSAGE
    payload_size = ResponsePayloadSize.ACCEPT_MESSAGE_SIZE.value

    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, payload_size)
    response_payload = ResponsePayload({"client_id": client_id}, code, payload_size)

    logger.info("Sending accept message response")

    return response_header, response_payload


def handle_successful_registration(client_id: bytes) -> (ResponseHeader, ResponsePayload):
    """
   Create a response for a successful client registration.

   Args:
       client_id (bytes): The unique identifier of the registered client.

   Returns:
       tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header
           and payload for the successful registration.
    """

    code = ResponseCode.REGISTRATION_SUCCEEDED
    length = ResponsePayloadSize.REGISTRATION_SUCCEEDED_SIZE.value

    # Construct the response header and payload
    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, length)
    response_payload = ResponsePayload({"client_id": client_id}, code, length)

    return response_header, response_payload


def handle_failed_registration() -> (ResponseHeader, ResponsePayload):
    """
    Create a response for a failed client registration.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header
            and an empty payload for the failed registration.
    """

    code = ResponseCode.REGISTRATION_FAILED
    length = ResponsePayloadSize.REGISTRATION_FAILED_SIZE.value

    # Construct the response payload with optional error message
    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, length)
    response_payload = ResponsePayload({}, code, length)

    return response_header, response_payload


def handle_rejected_reconnect(client_id: bytes) -> (ResponseHeader, ResponsePayload):
    """
    Create a response for a rejected reconnection request.

    Args:
        client_id (bytes): The client ID.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.
    """

    code = ResponseCode.RECONNECT_REQUEST_REJECTED
    length = ResponsePayloadSize.RECONNECT_REQUEST_REJECTED_SIZE.value

    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, length)
    response_payload = ResponsePayload({"client_id": client_id}, code, length)

    return response_header, response_payload


def handle_accepted_reconnect(client_id: bytes, client_table: ClientTable) -> \
        (ResponseHeader, ResponsePayload):
    """
    Handle a successful reconnection request.

    Args:
        client_id (bytes): The client ID.
        client_table (ClientTable): The client table to get the public key and update the AES key.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.

    """
    code = ResponseCode.RECONNECT_REQUEST_ACCEPT_AND_SEND_ENCRYPTED_AES_KEY
    length = ResponsePayloadSize.RECONNECT_REQUEST_ACCEPT_BASIC_SIZE.value  # The basic size

    public_key = client_table.get_public_key_according_to_client_id(client_id)

    # Check if the public key exists
    if public_key is None:
        raise ValueError("The public key is missing - cannot send encrypted AES key")

    # Generate a new AES key for the client and update the client table
    aes_key = generate_aes_key()
    client_table.update_client_aes_key(client_id, aes_key)

    # Encrypt the AES key with the public key
    aes_key_encrypted = encrypt_by_public_key(public_key, aes_key)

    length += len(aes_key_encrypted)  # Add the variable length of the AES key

    payload_content = {"client_id": client_id, "encrypted_symmetric_key": aes_key_encrypted}
    response_payload = ResponsePayload(payload_content, code, length)

    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, length)
    return response_header, response_payload


def is_registration_valid(client_name: str, client_table: ClientTable) -> bool:
    """
    Validate the client registration information.

    Args:
        client_name (str): The name of the client to register.
        client_table (ClientTable): The client table for checking existing names.

    Returns:
        bool: True if registration is valid, False otherwise.
    """
    return (is_valid_client_name(client_name) and not client_table.is_exist_client_name(
        client_name))


def is_reconnect_accepted(client_id: bytes, name: str, client_table: ClientTable) -> bool:
    """
   Check if a reconnection request is accepted based on the client ID and name.

   Args:
       client_id (bytes): The client ID to check.
       name (str): The name associated with the client ID.
       client_table (ClientTable): The client table to verify the client information.

   Returns:
       bool: True if the reconnection is accepted, False otherwise.
   """

    # Check if the client ID exists in the database
    if not client_table.is_exist_client_id(client_id):
        return False

    # Check if the name matches the client ID
    return client_table.get_name_according_to_client_id(client_id) == name


def get_file_received_response(client_id: bytes, file_name: str, content_size: int, path: str,
                               file_table: FileTable) -> (ResponseHeader, ResponsePayload):
    """
    Create a response for a received file.

    Args:
        client_id (bytes): The client ID.
        file_name (str): The name of the file.
        content_size (int): The size of the file content.
        path (str): The path of the file.
        file_table (FileTable): The file table to insert the file.

    Returns:
        tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and payload.
    """

    LAST_PACKET_TRACKER[client_id] = 0  # Reset for the client
    file_table.insert_file(client_id, file_name, path)

    check_sum = calculate_file_checksum(path)

    code = ResponseCode.FILE_RECEIVED
    length = ResponsePayloadSize.FILE_RECEIVED_SIZE.value

    payload_content = {
        "client_id": client_id,
        "content_size": content_size,
        "file_name": file_name,
        "check_sum": check_sum
    }

    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, length)
    response_payload = ResponsePayload(payload_content, code, length)

    return response_header, response_payload


def validate_the_order_of_packets(client_id: bytes, packet_number: int) -> None:
    """
    Validate the order of the packets.

    Args:
        client_id (bytes): The client ID.
        packet_number (int): The number of the packet.

    Raises:
        ValueError: If the packets are not in the correct order.
    """

    if packet_number != LAST_PACKET_TRACKER[client_id] + 1:
        raise ValueError("The packets are not in the correct order")


def general_error_response() -> (ResponseHeader, ResponsePayload):
    """
    Create a general error response. If an error occurs during the processing of a request, this
    response will be sent back to the client.

    Returns:
        Tuple[ResponseHeader, ResponsePayload]: A tuple containing the response header and
        payload of the general error response.
    """

    code = ResponseCode.GENERAL_ERROR
    length = ResponsePayloadSize.GENERAL_ERROR_SIZE.value
    response_header = ResponseHeader(ResponseHeader.SERVER_VERSION, code, length)
    response_payload = ResponsePayload({}, code, length)
    return response_header, response_payload


def validate_arguments(request_header: RequestHeader, request_payload: RequestPayload,
                       database: Database) -> None:
    """
    Validate the arguments of the request.

    Args:
        request_header (RequestHeader): The header of the request.
        request_payload (RequestPayload): The payload of the request.
        database (Database): The database object.

    """
    # Check the types of the arguments
    check_arguments_types({
        "request_header": (request_header, (RequestHeader,)),
        "request_payload": (request_payload, (RequestPayload,)),
        "database": (database, (Database,))
    }, inspect.currentframe().f_lineno, FILE_NAME)


def validate_client_id(client_id: bytes, client_table: ClientTable) -> None:
    """
    Validate if the client ID exists in the database.

    Args:
        client_id (bytes): The client ID to validate.
        client_table (ClientTable): The client table to check the client ID.

    """
    if not client_table.is_exist_client_id(client_id):
        raise ValueError("The client ID does incorrect, so we wont be able to handle your request")


def validate_public_key(request_payload: RequestPayload) -> None:
    """
    Validate the public key in the request payload.

    Args:
        request_payload (RequestPayload): The request payload to validate.

    """

    public_key = request_payload.payload_content.get("public_key")
    if public_key is None:
        raise ValueError("The public key is missing in send public key request payload.")


def validate_fields_in_payload_content(payload_content: dict, fields_of_dict: list) -> None:
    """
    Validate the fields in the payload content of the request.

    Args:
        payload_content (dict): The payload content of the request.
        fields_of_dict (list): The fields to validate in the payload content.

    """

    for field_of_dict in fields_of_dict:
        if payload_content.get(field_of_dict) is None:
            raise ValueError(f"The field {field_of_dict} is missing in the request payload content")


def validate_file_of_client_exists(client_id: bytes, file_name: str, file_table: FileTable) -> None:
    """
    Validate if the file of the client exists in the database.

    Args:
        client_id (bytes): The client ID.
        file_name (str): The name of the file.
        file_table (FileTable): The file table to check the file.

    """

    if not file_table.is_exist_file(client_id, file_name):
        raise ValueError(f"The file '{file_name}' does not exist for the client")

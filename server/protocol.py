import os
import inspect
import struct
from typing import Dict, Union
from enum import Enum
from utils.validation_utils import check_arguments_types

FILE_NAME = os.path.basename(__file__)


class RequestCode(Enum):
    """
    Enum class for various request codes used in the communication protocol.

    This enum class defines different types of requests that can be made by a
    client when communicating with the server. Each request type is associated with
    a unique numeric value, allowing the server to identify the specific action
    requested by the client.
    """

    REGISTRATION = 825
    SEND_PUBLIC_KEY = 826
    RECONNECT = 827
    SEND_FILE = 828
    VALID_CRC = 900
    INVALID_CRC = 901
    INVALID_CRC_IN_THE_FOURTH_TIME = 902


class ResponseCode(Enum):
    """
    Enum class for various response codes used in the communication protocol.

    This enum class defines different types of responses that can be sent by the
    server when communicating with the client. Each response type is associated with
    a unique numeric value, allowing the client to identify the result of the action
    that was requested previously by him.
    """

    REGISTRATION_SUCCEEDED = 1600
    REGISTRATION_FAILED = 1601
    RECEIVED_PUBLIC_KEY_AND_SEND_ENCRYPTED_AES_KEY = 1602
    FILE_RECEIVED = 1603
    ACCEPT_MESSAGE = 1604
    RECONNECT_REQUEST_ACCEPT_AND_SEND_ENCRYPTED_AES_KEY = 1605
    RECONNECT_REQUEST_REJECTED = 1606
    GENERAL_ERROR = 1607


class ResponsePayloadSize(Enum):
    """
    Enum class that defines the sizes of various response payloads.

    This enum contains the sum of all the sizes of the constant fields of the request's
    payload. Some fields may have variable sizes, and their sizes will be added to the
    constant sizes as needed. This helps in determining the total size required for
    each request type.
    """
    REGISTRATION_SUCCEEDED_SIZE = 16
    REGISTRATION_FAILED_SIZE = 0
    SEND_ENCRYPTED_AES_KEY_BASIC_SIZE = 16  # Variable size
    FILE_RECEIVED_SIZE = 279
    ACCEPT_MESSAGE_SIZE = 16
    RECONNECT_REQUEST_ACCEPT_BASIC_SIZE = 16  # Variable size
    RECONNECT_REQUEST_REJECTED_SIZE = 16
    GENERAL_ERROR_SIZE = 0


class RequestHeader:
    """
    Class that represents the header of a request in the communication protocol,
    that we have implemented.

    The request header contains information about the request, such as the client ID,
    the version of the client, the request code, and the size of the payload that

    Attributes:
        client_id (bytes): The ID of the client making the request.
        version_of_client (int): The version of the client making the request.
        code (RequestCode): The code associated with the request.
        payload_size (int): The size of the payload associated with the

    Methods:
        unpack_header(header_data: bytes) -> 'RequestHeader': Unpack the header data
        from the given bytes and return a RequestHeader object.

    Constants:
        HEADER_SIZE (int): The size of the request header in bytes.

    """

    HEADER_SIZE = 23

    def __init__(self, client_id: bytes, version_of_client: int, code: RequestCode,
                 payload_size: int) -> None:
        """
        Initialize the RequestHeader object with the given values.
        
        Args:
            client_id (bytes): The ID of the client making the request.
            version_of_client (int): The version of the client making the request.
            code (RequestCode): The code associated with the request.
            payload_size (int): The size of the payload associated with the
        """

        self.validate_arguments(client_id, version_of_client, code, payload_size)

        self.client_id = client_id
        self.version_of_client = version_of_client
        self.code = code
        self.payload_size = payload_size

    @staticmethod
    def validate_arguments(client_id: bytes, version_of_client: int, code: RequestCode,
                           payload_size: int) -> None:
        """
        Validate the arguments of the RequestHeader object.

        Args:
            client_id (bytes): The ID of the client making the request.
            version_of_client (int): The version of the client making the request.
            code (RequestCode): The code associated with the request.
            payload_size (int): The size of the payload associated with the
        """
        check_arguments_types({
            "client_id": (client_id, (bytes,)),
            "version_of_client": (version_of_client, (int,)),
            "code": (code, (RequestCode,)),
            "payload_size": (payload_size, (int,))
        },
            inspect.currentframe().f_lineno, FILE_NAME)

    @staticmethod
    def unpack_header(header_data: bytes) -> 'RequestHeader':
        """
        Unpack the header data from the given bytes and return a RequestHeader object.

        Args:
            header_data (bytes): The header data to unpack.

        Returns:
            RequestHeader: The unpacked RequestHeader object.
        """

        check_arguments_types({
            "header_data": (header_data, (bytes,))
        },
            inspect.currentframe().f_lineno, FILE_NAME)

        try:
            header_content = struct.unpack('<16sBHI', header_data)  # Unpack the header data
            client_id, version_of_client, code, payload_size = header_content
        except struct.error:
            raise ValueError("Invalid header data format of request")
        try:
            code = RequestCode(code)
        except ValueError:
            raise ValueError("Invalid request code")
        return RequestHeader(client_id, version_of_client, code, payload_size)


class RequestPayload:
    """
    Class that represents the payload of a request in the communication protocol
    that we have implemented.

    The request payload contains the actual data associated with the request, such as
    the name of the client, the public key of the client, the content of the file, etc.

    Attributes:
        payload_content (Dict[str, Union[str, bytes, int]]): The content of the payload.

    Methods:
        unpack_payload(payload_data: bytes, code: RequestCode) -> 'RequestPayload':
            Unpack the payload data from the given bytes and return a RequestPayload object.
        unpack_registration_request(payload_data: bytes) -> Dict[str, str]:
            Unpack the registration request payload data from the given bytes and return dictionary.
        unpack_send_public_key_request(payload_data: bytes) -> Dict[str, Union[str, bytes]]:
            Unpack the send public key request payload data from given bytes and return dictionary.
        unpack_reconnect_request(payload_data: bytes) -> Dict[str, str]:
            Unpack the reconnect request payload data from the given bytes and return a dictionary.
        unpack_send_file_request(payload_data: bytes) -> Dict[str, Union[str, bytes, int]]:
            Unpack the send file request payload data from the given bytes and return a dictionary.
        unpack_valid_crc_request(payload_data: bytes) -> Dict[str, str]:
            Unpack the CRC correct request payload data from the given bytes and return dictionary.
        unpack_invalid_crc_request(payload_data: bytes) -> Dict[str, str]:
            Unpack the invalid CRC request payload data from the given bytes and return dictionary.
        unpack_invalid_crc_in_the_fourth_time_request(payload_data: bytes) -> Dict[str, str]:
            Unpack the invalid CRC in the fourth time request payload data from the given bytes
            and return a dictionary.

    Constants:
        START_FILE_CONTENT_BYTE (int): The index of the first byte of the file content in the
            payload data, according to the protocol.
    """

    START_FILE_CONTENT_BYTE = 267

    def __init__(self, payload_content: Dict[str, Union[str, bytes, int]]) -> None:
        """
        Initialize the RequestPayload object with the given payload content.

        Args:
            payload_content (Dict[str, Union[str, bytes, int]]): The content of the payload.
            in format key:value
        """
        self.validate_arguments_for_request_payload(payload_content)
        self.payload_content = payload_content

    @staticmethod
    def validate_arguments_for_request_payload(
            payload_content: Dict[str, Union[str, bytes, int]]) -> None:
        """
        Validate the arguments of the RequestPayload object.

        Args:
            payload_content (Dict[str, Union[str, bytes, int]]): The content of the payload.
        """

        args_types = {"payload_content": (payload_content, (dict,))}
        args_elements_types_keys = {f"payload_content{i}": (key, (str,)) for i, key in
                                    enumerate(payload_content.keys())}
        args_elements_types_values = {f"payload_content{i}": (value, (str, bytes, int)) for i, value
                                      in enumerate(payload_content.values())}
        check_arguments_types(args_types | args_elements_types_keys | args_elements_types_values,
                              inspect.currentframe().f_lineno, FILE_NAME)

    @staticmethod
    def unpack_payload(payload_data: bytes, code: RequestCode) -> 'RequestPayload':
        """
        Unpack the payload data based on the request code.

        Args:
            payload_data (bytes): The raw bytes containing the payload.
            code (RequestCode): The code indicating the type of payload.

        Returns:
            RequestPayload: The unpacked RequestPayload object.

        Raises:
            ValueError: If the provided request code does not match any known codes.
        """

        check_arguments_types({
            "payload_data": (payload_data, (bytes,)),
            "code": (code, (RequestCode,))
        },
            inspect.currentframe().f_lineno, FILE_NAME)

        unpack_methods = {
            RequestCode.REGISTRATION: RequestPayload.unpack_registration_request,
            RequestCode.SEND_PUBLIC_KEY: RequestPayload.unpack_send_public_key_request,
            RequestCode.RECONNECT: RequestPayload.unpack_reconnect_request,
            RequestCode.SEND_FILE: RequestPayload.unpack_send_file_request,
            RequestCode.VALID_CRC: RequestPayload.unpack_valid_crc_request,
            RequestCode.INVALID_CRC: RequestPayload.unpack_invalid_crc_request,
            RequestCode.INVALID_CRC_IN_THE_FOURTH_TIME:
                RequestPayload.unpack_invalid_crc_in_the_fourth_time_request
        }
        func = unpack_methods.get(code)  # Call the appropriate unpacking method

        if func is None:
            raise ValueError("Invalid request code")

        try:
            payload_data = func(payload_data)
        except struct.error:
            raise ValueError("Invalid request payload data format of request")

        return RequestPayload(payload_data)

    @staticmethod
    def unpack_registration_request(payload_data: bytes) -> Dict[str, str]:
        """
        Unpack the registration request payload data from the given bytes and return a dictionary.

        Args:
            payload_data (bytes): The payload data to unpack.
        """
        name_bytes = struct.unpack('<255s', payload_data)[0]
        name = name_bytes.decode('ascii').rstrip('\x00')  # Remove null bytes if any
        return {"name": name}

    @staticmethod
    def unpack_send_public_key_request(payload_data: bytes) -> Dict[str, Union[str, bytes]]:
        """
        Unpack send public key request payload data from the given bytes and return a dictionary.
        
        Args:
            payload_data (bytes): The payload data to unpack.
        
        """

        name_bytes, public_key = struct.unpack('<255s160s', payload_data)
        name = name_bytes.decode('ascii').rstrip('\x00')
        return {"name": name, "public_key": public_key}

    @staticmethod
    def unpack_reconnect_request(payload_data: bytes) -> Dict[str, str]:
        """
        Unpack the reconnect request payload data from the given bytes and return a dictionary.
        
        Args:
            payload_data (bytes): The payload data to unpack.
        
        """

        name_bytes = struct.unpack('<255s', payload_data)[0]
        name = name_bytes.decode('ascii').rstrip('\x00')
        return {"name": name}

    @staticmethod
    def unpack_send_file_request(payload_data: bytes) -> Dict[str, Union[str, bytes, int]]:
        """
        Unpack the send file request payload data from the given bytes and return a dictionary.
        
        Args:
            payload_data (bytes): The payload data to unpack
             
        """

        # Unpack fixed-size fields
        (content_size, original_file_size, packet_number, total_packets,
         file_name_bytes) = struct.unpack('<IIHH255s',
                                          payload_data[:RequestPayload.START_FILE_CONTENT_BYTE])
        # Decode file name
        file_name = file_name_bytes.decode('ascii').rstrip('\x00')
        # Remaining content
        encrypted_content = payload_data[RequestPayload.START_FILE_CONTENT_BYTE:]
        return {
            "content_size": content_size,
            "original_file_size": original_file_size,
            "packet_number": packet_number,
            "total_packets": total_packets,
            "file_name": file_name,
            "encrypted_content": encrypted_content
        }

    @staticmethod
    def unpack_valid_crc_request(payload_data: bytes) -> Dict[str, str]:
        """
        Unpack the crc correct request payload data from the given bytes and return a dictionary.

        Args:
            payload_data (bytes): The payload data to unpack

        """
        file_name_bytes = struct.unpack('<255s', payload_data)[0]
        file_name = file_name_bytes.decode('ascii').rstrip('\x00')
        return {"file_name": file_name}

    @staticmethod
    def unpack_invalid_crc_request(payload_data: bytes) -> Dict[str, str]:
        """
        Unpack the crc correct request payload data from the given bytes and return a dictionary.

        Args:
            payload_data (bytes): The payload data to unpack

        """
        file_name_bytes = struct.unpack('<255s', payload_data)[0]
        file_name = file_name_bytes.decode('ascii').rstrip('\x00')
        return {"file_name": file_name}

    @staticmethod
    def unpack_invalid_crc_in_the_fourth_time_request(payload_data: bytes) -> Dict[str, str]:
        """
        Unpack the crc correct request payload data from the given bytes and return a dictionary.

        Args:
            payload_data (bytes): The payload data to unpack

        """

        # Unpack the file name - the same as the other invalid CRC
        return RequestPayload.unpack_invalid_crc_request(payload_data)


class ResponseHeader:
    """
    Class that represents the header of a response in the communication protocol,
    that we have implemented.

    The response header contains information about the response, such as the version of the server,
    the response code, and the size of the payload that will be sent to the client.

    Attributes:
        version (int): The version of the server.
        code (ResponseCode): The code associated with the response.
        payload_size (int): The size of the payload associated with the response.

    Methods:
        pack_header() -> bytes: Pack the header data and return it as bytes.

    Constants:
        SERVER_VERSION (int): The version of the server.
    """

    SERVER_VERSION = 3

    def __init__(self, version: int, code: ResponseCode, payload_size: int) -> None:
        """
        Initialize the ResponseHeader object with the given values.

        Args:
            version (int): The version of the server.
            code (ResponseCode): The code associated with the response.
            payload_size (int): The size of the payload associated with the response.

        """
        self.validate_arguments(version, code, payload_size)

        self.version = version
        self.code = code
        self.payload_size = payload_size

    @staticmethod
    def validate_arguments(version: int, code: ResponseCode, payload_size: int) -> None:
        """
        Validate the arguments of the ResponseHeader object.

        Args:
            version (int): The version of the server.
            code (ResponseCode): The code associated with the response.
            payload_size (int): The size of the payload associated with the response.

        """
        check_arguments_types({
            "version": (version, (int,)),
            "code": (code, (ResponseCode,)),
            "payload_size": (payload_size, (int,))
        },
            inspect.currentframe().f_lineno, FILE_NAME)

    def pack_header(self) -> bytes:
        """
        Pack the header data and return it as bytes.

        Returns:
            bytes: The packed header data.
        """

        version_of_server = self.version
        code = self.code.value
        payload_size = self.payload_size
        try:
            fmt = '<BHI'
            header_data = struct.pack(fmt, version_of_server, code, payload_size)
            return header_data
        except struct.error:
            raise ValueError("Invalid header data info for response")


class ResponsePayload:
    """
    Class that represents the payload of a response in the communication protocol,
    that we have implemented.

    The response payload contains the actual data associated with the response, such as
    the client ID, the encrypted AES key, the file name, etc.

    Attributes:
        payload_content (Dict[str, Union[str, bytes, int]]): The content of the payload.
        code (ResponseCode): The code associated with the response.
        payload_size (int): The size of the payload.

    Methods:
        pack_payload(code: ResponseCode) -> bytes: Pack the payload data and return it as bytes.
        pack_registration_success_response() -> bytes: Pack the registration success response
        data and return it as bytes.
        pack_registration_failed_response() -> bytes: Pack the registration failed response data
        and return it as bytes.
        pack_send_encrypted_aes_key_response() -> bytes: Pack send encrypted AES key response
        data and return it as bytes.
        pack_file_received_response() -> bytes: Pack the file received response data and return
        it as bytes.
        pack_accept_message_response() -> bytes: Pack the accept message response data and return
        it as bytes.
        pack_reconnect_request_accept() -> bytes: Pack the reconnect request accept response data
        and return it as bytes.
        pack_reconnect_request_rejected_response() -> bytes: Pack the reconnect request rejected
        response data and return it as bytes.
        pack_general_error_response() -> bytes: Pack the general error response data and return
         it as bytes.

    """

    def __init__(self, payload_content: Dict[str, Union[str, bytes, int]], code: ResponseCode,
                 payload_size: int) -> None:
        """
        Initialize the ResponsePayload object with the given values.

        Args:
            payload_content (Dict[str, Union[str, bytes, int]): The content of the payload.
            code (ResponseCode): The code associated with the response.
            payload_size (int): The size of the payload.

        """

        args_response_types = {"payload_content": (payload_content, (dict,))}
        args_elements_types_keys = {f"payload_content{i}": (key, (str,)) for i, key in
                                    enumerate(payload_content.keys())}
        args_elements_types_values = {f"payload_content{i}": (value, (str, bytes, int)) for i, value
                                      in enumerate(payload_content.values())}
        check_arguments_types(
            args_response_types | args_elements_types_keys | args_elements_types_values,
            inspect.currentframe().f_lineno, FILE_NAME)

        self.payload_content = payload_content
        self.code = code
        self.payload_size = payload_size

    def pack_payload(self, code: ResponseCode) -> bytes:
        """
        Pack the payload data and return it as bytes.

        Args:
            code (ResponseCode): The code associated with the response.

        Returns:
            bytes: The packed payload data.
        """

        unpack_methods = {
            ResponseCode.REGISTRATION_SUCCEEDED: self.pack_registration_success_response,
            ResponseCode.REGISTRATION_FAILED: ResponsePayload.pack_registration_failed_response,
            ResponseCode.RECEIVED_PUBLIC_KEY_AND_SEND_ENCRYPTED_AES_KEY:
                self.pack_send_encrypted_aes_key_response,
            ResponseCode.FILE_RECEIVED: self.pack_file_received_response,
            ResponseCode.ACCEPT_MESSAGE: self.pack_accept_message_response,
            ResponseCode.RECONNECT_REQUEST_ACCEPT_AND_SEND_ENCRYPTED_AES_KEY:
                self.pack_reconnect_request_accept,
            ResponseCode.RECONNECT_REQUEST_REJECTED: self.pack_reconnect_request_rejected_response,
            ResponseCode.GENERAL_ERROR: ResponsePayload.pack_registration_failed_response
        }
        # Call the appropriate packing method
        func = unpack_methods.get(code)

        if func is None:
            raise ValueError("Invalid Response code")

        try:
            data = func()
            return data
        except struct.error:
            raise ValueError("Invalid payload data format for response")

    def pack_registration_success_response(self) -> bytes:
        """
        Pack the registration success response data and return it as bytes.

        Returns:
            bytes: The packed registration success response data containing the client ID.
        """
        client_id_data = self.payload_content['client_id']
        fmt = '<16s'
        return struct.pack(fmt, client_id_data)

    @staticmethod
    def pack_registration_failed_response() -> bytes:
        """
        Pack the registration failed response data and return it as bytes.

        Returns:
            bytes: The packed registration failed response data, currently empty.
        """
        return b''

    def pack_send_encrypted_aes_key_response(self) -> bytes:
        """
        Pack the response data for sending an encrypted AES key and return it as bytes.

        Returns:
            bytes: The packed response data containing the client ID and the encrypted AES key.
        """
        client_id_data = self.payload_content['client_id']
        aes_key_encrypted_data = self.payload_content['encrypted_symmetric_key']
        fmt = f'<{16}s{len(aes_key_encrypted_data)}s'
        return struct.pack(fmt, client_id_data, aes_key_encrypted_data)

    def pack_file_received_response(self) -> bytes:
        """
        Pack the response data for confirming that a file has been received and return it as bytes.

        Returns:
            bytes: The packed response data containing the client ID, content size, file name,
            and checksum.
        """
        client_id_data = self.payload_content['client_id']
        content_size_data = self.payload_content['content_size']
        file_name = self.payload_content['file_name'].encode('ascii')
        file_name_data = file_name.ljust(255, b'\x00')
        check_sum_data = self.payload_content['check_sum']
        fmt = '<16sI255sI'
        return struct.pack(fmt, client_id_data, content_size_data, file_name_data, check_sum_data)

    def pack_accept_message_response(self) -> bytes:
        """
        Pack the accept message response data and return it as bytes.

        Returns:
            bytes: The packed accepted message response data containing the client ID.
        """
        client_id_data = self.payload_content['client_id']
        fmt = '<16s'
        return struct.pack(fmt, client_id_data)

    def pack_reconnect_request_accept(self) -> bytes:
        """
        Pack the response data for accepting a reconnect request and return it as bytes.

        Returns:
            bytes: The packed response data containing the client ID and the encrypted AES key.
        """
        client_id_data = self.payload_content['client_id']
        aes_key_encrypted_data = self.payload_content['encrypted_symmetric_key']
        fmt = f'<{16}s{len(aes_key_encrypted_data)}s'
        return struct.pack(fmt, client_id_data, aes_key_encrypted_data)

    def pack_reconnect_request_rejected_response(self) -> bytes:
        """
        Pack the response data for rejecting a reconnect request and return it as bytes.

        Returns:
            bytes: The packed response data containing the client ID to indicate rejection.
        """
        client_id_data = self.payload_content['client_id']
        fmt = '<16s'
        return struct.pack(fmt, client_id_data)

    @staticmethod
    def pack_general_error_response() -> bytes:
        """
        Pack the general error response data and return it as bytes.

        Returns:
            bytes: The packed general error response data, currently empty.
        """
        return b''

import socket
import threading
import logging
import os
import inspect
import handle_requests
from protocol import (RequestHeader, RequestPayload, ResponseHeader, ResponsePayload,
                      ResponseCode)
from database import Database
from utils.validation_utils import check_arguments_types


FILE_NAME = os.path.basename(__file__)
logger = logging.getLogger(__name__)


class Server:
    """
        This class represents the server that will receive requests from clients and send responses
        back to them. The server is responsible for storing information about the clients and the
        files that clients send (in a database).

        Attributes:
            port (int): The port number on which the server will listen for incoming connections.
            host (str): The host address of the server.
            socket (socket.socket): The socket object that the server will use to listening for
            incoming connections.
            database (Database): The database manager object that the server will use to store
            information about the clients and the files that clients send

        Methods:
            receive_data: Static method that Receive a specified number of bytes from the
            connection.
            send_data: Static method that send data through the connection ensuring all data is
            sent.
            receive_header: Receive the request header from the client.
            receive_payload: Receive the request payload from the client.
            send_header: Send the response header to the client.
            send_payload: Send the response payload to the client.
            receive_request: Receive the request from the client.
            send_response: Send the response to the client.
            process_request: Process the request and return the response.
            should_end_communication: Check if the communication with the client should
            be ended.
            need_to_send_response: Check if the response should be sent to the client.
            handle_client: Handle the client connection, receive requests, process them, and send
            responses back to the client.
            start_server: Start the server. The server will listen for incoming connections and
            receive requests (and will be responsible for handling them).

        Constants:
            BUFFER (int): Buffer size for sending and receiving data from the client.
            DATABASE_NAME (str): Database file name.
            SERVER_VERSION (int): Server version.
    """

    BUFFER = 1024  # Buffer size for sending and receiving data
    DATABASE_NAME = "defensive.db"  # Database file name
    SERVER_VERSION = 3  # Server version

    def __init__(self, port: int) -> None:
        """
        Initialize the server with the given port number.

        Args:
            port (int): The port number on which the server will listen for incoming connections.
        """
        check_arguments_types({"port": (port, (int,))}, inspect.currentframe().f_lineno, FILE_NAME)
        self.port = port
        self.host = "127.0.0.1"  # Define the host address
        self.database = Database(Server.DATABASE_NAME)
        self.threads = []  # List to keep track of threads
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    @staticmethod
    def receive_data(conn: socket.socket, size: int) -> bytes:
        """
        Receive a specified number of bytes from the connection.

        Args:
            conn (socket.socket): The connection object.
            size (int): The number of bytes to receive.

        Returns:
            bytes: The received data that was get from the client.
        """

        data = b''
        while size > 0:
            chunk_size = min(size, Server.BUFFER)
            chunk = conn.recv(chunk_size)
            if not chunk:
                raise ConnectionError("Connection closed by the client.")
            data += chunk
            size -= len(chunk)
        return data

    @staticmethod
    def send_data(conn: socket.socket, data: bytes) -> None:
        """
        Send data through the connection ensuring all data is sent.

        Args:
            conn (socket.socket): The connection object.
            data (bytes): The data to send.
        """

        total_sent = 0
        total_length = len(data)
        while total_sent < total_length:
            sent = conn.send(data[total_sent:total_sent + Server.BUFFER])
            if sent == 0:
                raise ConnectionError("Connection closed by the client.")
            total_sent += sent

    def receive_header(self, conn: socket.socket) -> RequestHeader:
        """
        Receive the request header from the client.

        Args:
            conn (socket.socket): The connection object.
        """

        header_data = self.receive_data(conn, RequestHeader.HEADER_SIZE)
        return RequestHeader.unpack_header(header_data)

    def receive_payload(self, conn: socket.socket, request_header: RequestHeader) -> RequestPayload:
        """
        Receive the request payload from the client.

        Args:
            conn (socket.socket): The connection object.
            request_header (RequestHeader): The request header object.

        Returns:
            RequestPayload: The request payload object.
        """

        payload_data = self.receive_data(conn, request_header.payload_size)
        return RequestPayload.unpack_payload(payload_data, request_header.code)

    def send_header(self, conn: socket.socket, response_header: ResponseHeader) -> None:
        """
        Send the response header to the client.

        Args:
            conn (socket.socket): The connection object.
            response_header (ResponseHeader): The response header object.

        """

        header_data = response_header.pack_header()
        self.send_data(conn, header_data)

    def send_payload(self, conn: socket.socket, response_payload: ResponsePayload) -> None:
        """
        Send the response payload to the client.

        Args:
            conn (socket.socket): The connection object.
            response_payload (ResponsePayload): The response payload object.
        """

        payload_data = response_payload.pack_payload(response_payload.code)
        self.send_data(conn, payload_data)

    def receive_request(self, conn: socket.socket) -> (RequestHeader, RequestPayload):
        """
        Receive the request from the client.

        Args:
            conn (socket.socket): The connection object.

        Returns:
            Tuple[RequestHeader, RequestPayload]: The request header and payload objects.
        """

        request_header = self.receive_header(conn)
        request_payload = self.receive_payload(conn, request_header)
        return request_header, request_payload

    def send_response(self, conn: socket.socket, response_header: ResponseHeader,
                      response_payload: ResponsePayload) -> None:
        """
        Send the response to the client.

        Args:
            conn (socket.socket): The connection object.
            response_header (ResponseHeader): The response header object.
            response_payload (ResponsePayload): The response payload object.
        """

        self.send_header(conn, response_header)
        self.send_payload(conn, response_payload)

    def process_request(self, request_header: RequestHeader, request_payload: RequestPayload) -> \
            (ResponseHeader, ResponsePayload):
        """
        Process the request and return the response.

        Args:
            request_header (RequestHeader): The request header object.
            request_payload (RequestPayload): The request payload object.

        Returns:
            Tuple[ResponseHeader, ResponsePayload]: The response header and payload objects.
        """

        return handle_requests.get_response(request_header, request_payload, self.database)

    @staticmethod
    def should_end_communication(response_header: ResponseHeader) -> bool:
        """
        Check if the communication with the client should be ended.

        Args:
            response_header (ResponseHeader): The response header object.

        Returns:
            bool: True if the communication should be ended, False otherwise.
        """

        end_codes = [ResponseCode.ACCEPT_MESSAGE, ResponseCode.REGISTRATION_FAILED]
        return response_header.code in end_codes

    @staticmethod
    def need_to_send_response(response_header: ResponseHeader,
                              response_payload: ResponsePayload) -> bool:
        """
        Check if the response should be sent to the client.
        (if we should not send response, these objects will be None)

        Args:
            response_header (ResponseHeader): The response header object.
            response_payload (ResponsePayload): The response payload object.

        Returns:
            bool: True if the response should be sent, False otherwise.
        """

        return response_header is not None and response_payload is not None

    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        """
        Handle the client connection, receive requests, process them, and send responses back
        to the client.

        Args:
            conn (socket.socket): The connection object.
            addr (tuple): The address of the client.
        """

        try:
            check_arguments_types({"conn": (conn, (socket.socket,)), "addr": (addr, (tuple,))},
                                  inspect.currentframe().f_lineno, FILE_NAME)

            logger.info(f"{addr} connected to the server")

            flag = True
            while flag:
                request_header, request_payload = self.receive_request(conn)
                response_header, response_payload = self.process_request(request_header,
                                                                         request_payload)

                if not self.need_to_send_response(response_header, response_payload):
                    continue

                if self.should_end_communication(response_header):
                    flag = False

                self.send_response(conn, response_header, response_payload)

        except ConnectionError:
            logger.error("Client disconnected unexpectedly")

        except Exception as e:
            logger.error("General error occurred while handling the client - ", e)
            response_header, response_payload = handle_requests.general_error_response()
            self.send_response(conn, response_header, response_payload)

        finally:
            conn.close()
            logger.info(f"Connection closed by {addr}")

    def start_server(self) -> None:
        """
        Start the server. The server will listen for incoming connections and receive requests
        (and will be responsible for handling them).

        """
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen()
            logger.info(f"Server started on {self.host}:{self.port}")

            if not self.database.is_database_exist():
                self.database.create_database()

            while True:
                conn, addr = self.socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()
                self.threads.append(client_thread)

        except Exception as e:
            logger.error(f"Error in the server server: {e}")

        finally:
            self.clean_resources()
            logger.info("Server closed")

    def clean_resources(self):
        """
        Clean the resources of the server.
        """
        for thread in self.threads:
            thread.join()

        if self.socket:
            self.socket.close()

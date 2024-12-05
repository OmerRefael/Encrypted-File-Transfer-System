import sqlite3
import datetime
import os
import inspect
from typing import Optional, List, Any
from utils.validation_utils import check_arguments_types


FILE_NAME = os.path.basename(__file__)


class Database:
    def __init__(self, database_name="defensive.db"):
        check_arguments_types({
            "database_name": (database_name, (str,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        self.database_name = database_name
        self.client_table = ClientTable(self.database_name)
        self.file_table = FileTable(self.database_name)

    def create_database(self) -> None:
        self.client_table.create_client_table()
        self.file_table.create_file_table()

    def is_database_exist(self) -> bool:
        return os.path.exists(self.database_name)


class BaseTable:
    def __init__(self, database_name: str):
        self.database_name = database_name

    def connect_to_database(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_name)

    def execute_query(self, query: str, args: tuple) -> List[Any]:

        # Check the types of the arguments
        check_arguments_types({
            "query": (query, (str,)),
            "args": (args, (tuple,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        try:
            with self.connect_to_database() as connection:
                cursor = connection.cursor()
                cursor.execute(query, args)
                return cursor.fetchall()

        except sqlite3.Error as e:  # Catch specific exceptions
            raise Exception(f"Failed to execute query: '{query}' with args: {args}. Error: {e}")

    def execute_script(self, query: str, args: tuple) -> None:

        # Check the types of the arguments
        check_arguments_types({
            "query": (query, (str,)),
            "args": (args, (tuple,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        try:
            with self.connect_to_database() as connection:
                cursor = connection.cursor()
                cursor.execute(query, args)
                connection.commit()
        except sqlite3.Error as e:  # Catch specific exceptions
            raise Exception(f"Failed to execute query: '{query}' with args: {args}. Error: {e}")


class ClientTable(BaseTable):
    def create_client_table(self) -> None:
        create_client_table_command = """ CREATE TABLE clients (
            id BLOB NOT NULL PRIMARY KEY,
            name CHAR(255) NOT NULL UNIQUE,
            public_key BLOB,
            last_seen DATETIME NOT NULL,
            aes_key BLOB
        );"""
        self.execute_script(create_client_table_command, ())

    def insert_client(self, user_id: bytes, name: str, public_key: Optional[bytes],
                      aes_key: Optional[bytes]) -> bool:

        # Check the types of the arguments
        check_arguments_types({
            "user_id": (user_id, (bytes,)),
            "name": (name, (str,)),
            "public_key": (public_key, (bytes, type(None))),
            "aes_key": (aes_key, (bytes, type(None)))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        insert_client_command = """INSERT INTO clients (id, name, public_key, last_seen, 
        aes_key) VALUES (?, ?, ?, ?, ?)"""
        try:
            self.execute_script(insert_client_command, (user_id, name, public_key,
                                                        datetime.datetime.now(), aes_key))
            return True
        except Exception as e:
            print("ERROR:", e)
            return False

    def is_exist_client_id(self, client_id: bytes) -> bool:

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        is_exist_client_id_command = """SELECT 1 FROM clients WHERE id = ?"""
        return bool(self.execute_query(is_exist_client_id_command, (client_id,)))

    def is_exist_client_name(self, name: str) -> bool:

        # Check the types of the arguments
        check_arguments_types({
            "name": (name, (str,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        is_exist_client_name_command = """SELECT 1 FROM clients WHERE name = ?"""
        return bool(self.execute_query(is_exist_client_name_command, (name,)))

    def update_last_seen(self, client_id: bytes) -> None:

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        update_last_seen_command = """UPDATE clients SET last_seen = ? WHERE id = ?"""
        self.execute_script(update_last_seen_command, (datetime.datetime.now(), client_id))

    def update_client_public_key(self, client_id: bytes, public_key: bytes) -> None:
        """Update the public key of the client."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,)),
            "public_key": (public_key, (bytes,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        update_client_public_key_command = """UPDATE clients SET public_key = ? WHERE id = ?"""
        self.execute_script(update_client_public_key_command, (public_key, client_id))

    def update_client_aes_key(self, client_id: bytes, aes_key: bytes) -> None:
        """Update the AES key of the client."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,)),
            "aes_key": (aes_key, (bytes,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        update_client_aes_key_command = """UPDATE clients SET aes_key = ? WHERE id = ?"""
        self.execute_script(update_client_aes_key_command, (aes_key, client_id))

    def get_list_of_clients(self) -> list:
        """Get the list of all the clients in the database."""
        get_clients_command = """SELECT * FROM clients"""
        return self.execute_query(get_clients_command, ())

    def get_name_according_to_client_id(self, client_id: bytes) -> str:
        """Get the name according to the client ID."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        get_name_according_to_client_id_command = """SELECT name FROM clients WHERE id = ?"""
        return self.execute_query(get_name_according_to_client_id_command, (client_id,))[0][0]

    def get_public_key_according_to_client_id(self, client_id: bytes) -> bytes:
        """Get the public key according to the client ID."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        get_public_key_according_to_client_id_command = """SELECT public_key FROM clients WHERE  
        id = ?"""
        return self.execute_query(get_public_key_according_to_client_id_command, (client_id,))[0][0]

    def get_aes_key_according_to_client_id(self, client_id: bytes) -> bytes:
        """Get the AES key according to the client ID."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        get_aes_key_according_to_client_id_command = """SELECT aes_key FROM clients WHERE id = ?"""
        return self.execute_query(get_aes_key_according_to_client_id_command, (client_id,))[0][0]


class FileTable(BaseTable):
    def create_file_table(self) -> None:
        create_file_table_command = """CREATE TABLE files (
            id BLOB NOT NULL,
            file_name CHAR(255) NOT NULL,
            path_name CHAR(255) NOT NULL,
            verified BOOLEAN DEFAULT FALSE
        );"""
        self.execute_script(create_file_table_command, ())

    def insert_file(self, client_id: bytes, file_name: str, path_name: str,
                    verified: bool = False) -> None:
        """Insert a file into the database."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,)),
            "file_name": (file_name, (str,)),
            "path_name": (path_name, (str,)),
            "verified": (verified, (bool,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        insert_file_command = """INSERT INTO files (id, file_name, path_name, verified) VALUES  (
        ?, ?, ?, ?);"""
        self.execute_script(insert_file_command, (client_id, file_name, path_name, verified))

    def set_file_as_verified(self, client_id: bytes, file_name: str) -> None:
        """Set the file as verified."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,)),
            "file_name": (file_name, (str,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        set_file_as_verified_command = """UPDATE files SET verified = ? WHERE id = ? AND  
        file_name = ?"""
        self.execute_script(set_file_as_verified_command, (True, client_id, file_name))

    def is_exist_file(self, client_id: bytes, file_name: str) -> bool:
        """Check if the file exists in the database."""

        # Check the types of the arguments
        check_arguments_types({
            "client_id": (client_id, (bytes,)),
            "file_name": (file_name, (str,))
        }, inspect.currentframe().f_lineno, FILE_NAME)

        is_exist_file_command = """SELECT 1 FROM files WHERE id = ? AND file_name = ?"""
        return bool(self.execute_query(is_exist_file_command, (client_id, file_name)))

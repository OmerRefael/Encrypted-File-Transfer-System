import uuid


def generate_client_id(clients: list) -> bytes:
    """
    Generate a unique client ID.

    Args:
        clients (list): A list of clients, where each client is a tuple of the form (client_id, ...).

    Returns:
        bytes: A unique client ID.
    """
    while True:
        client_id = uuid.uuid4()
        if not any(client[0] == client_id for client in clients):
            return client_id.bytes
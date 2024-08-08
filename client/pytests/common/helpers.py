"""
Helper functions module tests.
"""

import binascii
import json
import os
import random
import re
import string

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common.consts import ReservedChars, fake


def extract_hash(stdout):
    """
    Extracts a SHA-256 hash from the given string.

    :param stdout: The string from which to extract the hash.
    :return: The extracted hash if found, otherwise None.
    """
    if not isinstance(stdout, str) or not stdout.strip():
        return None
    pattern = r'"([A-Fa-f0-9]{64})"'
    match = re.search(pattern, stdout)
    return match.group(1) if match else None


def get_peers_config_files(path_to_configs):
    """
    Returns a list of config file paths from the given directory.
    """
    config_files = []
    for entry in os.listdir(path_to_configs):
        if entry.endswith(".json") and "config_to_peer" in entry:
            config_files.append(os.path.join(path_to_configs, entry))
    return config_files


def read_isi_from_json(file_path):
    """
    Reads ISI instruction from a JSON file.

    :param file_path: Path to the JSON file containing ISI instruction.
    :return: Dictionary with ISI instruction.
    """
    with open(file_path, "r", encoding="utf-8") as file:
        isi_data = json.load(file)
    return isi_data


def write_isi_to_json(isi_data, file_path):
    """
    Writes ISI instruction to a JSON file.

    :param isi_data: Dictionary with ISI instruction.
    :param file_path: Path to save the JSON file.
    """
    if not isinstance(isi_data, list):
        isi_data = [isi_data]
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(isi_data, file, indent=4)


def generate_random_string_with_reserved_char():
    """
    Generate a random string with a reserved character.
    """
    temp_str = fake.word()
    letter = random.choice(ReservedChars.SPECIAL.value)
    random_position = random.randint(0, len(temp_str))
    new_string = temp_str[:random_position] + letter + temp_str[random_position:]
    return new_string


def generate_random_string_with_whitespace():
    """
    Generate a random string with a whitespace character.
    """
    temp_str = fake.word()
    letter = random.choice(ReservedChars.WHITESPACES.value)
    random_position = random.randint(0, len(temp_str))
    new_string = temp_str[:random_position] + letter + temp_str[random_position:]
    return new_string


def generate_public_key():
    """
    Generate a public key using Ed25519PrivateKey.
    """
    public_key = binascii.hexlify(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode()
    return "ed0120" + public_key.upper()


def generate_random_string(length, allowed_chars):
    """
    Generate a random string with the specified length and characters.
    """
    return "".join(random.choice(allowed_chars) for _ in range(length))


def generate_random_string_without_reserved_chars(length):
    """
    Generate a random string with the specified length, excluding reserved characters.
    """
    allowed_chars = [
        c
        for c in [*string.ascii_letters, *string.digits]
        if c not in ReservedChars.ALL.value
    ]
    return generate_random_string(length, allowed_chars)


def fake_name():
    """
    Generate a fake name.
    """
    return fake.word()


def fake_asset_name():
    """
    Generate a fake asset name.
    """
    word = fake.word()
    return word[:3].upper()


def not_existing_name():
    """
    Generate a non-existing name.
    """
    return "not_existing_name"


def key_with_invalid_character_in_key(public_key, random_character):
    """
    Replace the last character of a public key with a random character.
    """
    return public_key[:-1] + random_character


def name_with_uppercase_letter(name):
    """
    Change one random letter in a name to uppercase.
    """
    random_position = random.randint(0, len(name) - 1)
    name = (
        name[:random_position]
        + name[random_position].upper()
        + name[random_position + 1 :]
    )
    return name

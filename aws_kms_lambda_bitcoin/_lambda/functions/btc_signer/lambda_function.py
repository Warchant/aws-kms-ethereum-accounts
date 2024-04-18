import logging
import os
import boto3

session = boto3.session.Session()

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def get_kms_public_key(key_id: str) -> bytes:
    client = boto3.client("kms")

    response = client.get_public_key(KeyId=key_id)

    return response["PublicKey"]


def sign_kms(key_id: str, msg_hash: bytes) -> dict:
    client = boto3.client("kms")

    response = client.sign(
        KeyId=key_id,
        Message=msg_hash,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )

    return response


def lambda_handler(event, context):
    _logger.debug("incoming event: {}".format(event))

    key_id = os.getenv("KMS_KEY_ID")
    if not key_id:
        raise ValueError("missing `KMS_KEY_ID` environment variable")

    message_hex: str = event.get("message")
    if not message_hex:
        raise ValueError("missing `message` field (32 hexencoded bytes)")

    try:
        message: bytes = bytes.fromhex(message_hex)
    except Exception as e:
        raise ValueError("invalid hex encoding for `message` field") from e

    logging.info("input is valid")
    pub_key = get_kms_public_key(key_id)
    signature = sign_kms(key_id, message)
    return {
        "message": message_hex,
        "signature": signature["Signature"].hex(),
        "public_key": pub_key.hex(),
    }

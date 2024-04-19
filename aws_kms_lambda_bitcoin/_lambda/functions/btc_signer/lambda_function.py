import logging
import os
import boto3
import asn1tools
import hashlib
import hmac

session = boto3.session.Session()

LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
LOG_FORMAT = "%(levelname)s:%(lineno)s:%(message)s"
handler = logging.StreamHandler()

_logger = logging.getLogger()
_logger.setLevel(LOG_LEVEL)


def get_kms_public_key(key_id: str) -> bytes:
    client = boto3.client("kms")

    response = client.get_public_key(KeyId=key_id)

    return response


def sign_kms(key_id: str, msg_hash: bytes) -> dict:
    client = boto3.client("kms")

    response = client.sign(
        KeyId=key_id,
        Message=msg_hash,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )

    return response


def get_pubkey(pub_key: bytes) -> bytes:
    SUBJECT_ASN = """
    Key DEFINITIONS ::= BEGIN

    SubjectPublicKeyInfo  ::=  SEQUENCE  {
       algorithm         AlgorithmIdentifier,
       subjectPublicKey  BIT STRING
     }

    AlgorithmIdentifier  ::=  SEQUENCE  {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }

    END
    """

    key = asn1tools.compile_string(SUBJECT_ASN)
    key_decoded = key.decode("SubjectPublicKeyInfo", pub_key)

    pub_key_raw = key_decoded["subjectPublicKey"][0]
    return pub_key_raw  # this returns the raw 65 bytes public key


def get_signature(sig: bytes) -> bytes:
    SIGNATURE_ASN = """
    Signature DEFINITIONS ::= BEGIN

    Ecdsa-Sig-Value  ::=  SEQUENCE  {
           r     INTEGER,
           s     INTEGER  }

    END
    """
    signature_schema = asn1tools.compile_string(SIGNATURE_ASN)
    signature_decoded = signature_schema.decode("Ecdsa-Sig-Value", sig)
    r, s = signature_decoded["r"], signature_decoded["s"]
    r_bytes = r.to_bytes(32, byteorder="big")

    # https://medium.com/@ottosch/manually-creating-and-signing-a-bitcoin-transaction-87fbbfe46032
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # order of a curve
    # this breaks invariant that the sig size is 64 bytes (compact form)
    # if r_bytes[0] > 0x7f:
    #     r_bytes = b'\x00' + r_bytes
    if s > n / 2:
        s = n - s

    s_bytes = s.to_bytes(32, byteorder="big")
    return r_bytes + s_bytes


def verify_hmac(key: bytes, message: bytes, hmacsignature: bytes) -> bool:
    h = hmac.new(key, message, digestmod=hashlib.sha256)
    # use compare_digest to mitigate timing attacks
    return hmac.compare_digest(h.digest(), hmacsignature)


def check_hmac_signature(event: dict, message: bytes) -> None:
    hmac_key_str = os.getenv("HMAC_KEY")
    if hmac_key_str == "skip":
        logging.warning("Skipping HMAC verification")
        return

    if not hmac_key_str:
        raise ValueError("missing required `HMAC_KEY` environment variable")

    try:
        hmac_key = bytes.fromhex(hmac_key_str)
    except Exception as e:
        raise ValueError(
            "expected HMAC_KEY env var to be `skip` or hexencoded bytes"
        ) from e

    if len(hmac_key) < 16:
        raise ValueError("HMAC_KEY is too short - expected at least 16 bytes")

    try:
        hmac_signature = bytes.fromhex(event["hmac"])
    except Exception as e:
        raise ValueError("invalid hex encoding for `hmac` field") from e

    # do verify
    if not verify_hmac(hmac_key, message, hmac_signature):
        raise ValueError("invalid hmac signature")

    logging.info("HMAC signature is valid")


def lambda_handler(event: dict, context) -> dict:
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

    if len(message) != 32:
        raise ValueError("invalid message length (32 bytes expected)")

    # in prod we do not want anybody to run this lambda...
    # so we require a valid HMAC signature alongside the request
    check_hmac_signature(event, message)

    logging.info("input is valid")
    puboutput = get_kms_public_key(key_id)
    sigoutput = sign_kms(key_id, message)

    signature = get_signature(sigoutput["Signature"])
    assert len(signature) == 64

    pubkey = get_pubkey(puboutput["PublicKey"])
    assert len(pubkey) == 65

    return {
        "message": message_hex,
        "signature": signature.hex(),
        "public_key": pubkey.hex(),
    }

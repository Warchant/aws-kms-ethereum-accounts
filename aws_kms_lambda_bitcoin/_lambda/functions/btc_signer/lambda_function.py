import logging
import os
import boto3
import asn1tools

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
    SIGNATURE_ASN = '''
    Signature DEFINITIONS ::= BEGIN

    Ecdsa-Sig-Value  ::=  SEQUENCE  {
           r     INTEGER,
           s     INTEGER  }

    END
    '''
    signature_schema = asn1tools.compile_string(SIGNATURE_ASN)
    signature_decoded = signature_schema.decode('Ecdsa-Sig-Value', sig)
    r, s = signature_decoded['r'], signature_decoded['s']
    r_bytes = r.to_bytes(32, byteorder='big')

    # https://medium.com/@ottosch/manually-creating-and-signing-a-bitcoin-transaction-87fbbfe46032
    n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141  # order of a curve
    if r_bytes[0] > 0x7f:
        r_bytes = b'\x00' + r_bytes
    if s > n/2:
        s = n - s

    s_bytes = s.to_bytes(32, byteorder='big')
    return r_bytes + s_bytes


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

    if len(message) != 32:
        raise ValueError("invalid message length (32 bytes expected)")

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
        "public_key": pubkey.hex()
    }

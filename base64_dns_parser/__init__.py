import base64
import struct
from typing import Any, Dict, List, Tuple


def parse_name(data: bytes, offset: int) -> Tuple[str, int]:
    names = []
    idx = offset
    while True:
        length = data[idx]
        if length == 0:
            idx += 1
            break
        if length & 0xC0 == 0xC0:  # Compression pointer
            pointer = struct.unpack(">H", data[idx : idx + 2])[0] & 0x3FFF
            names.append(parse_name(data, pointer)[0])
            idx += 2
            break
        names.append(data[idx + 1 : idx + 1 + length].decode("ascii", errors="replace"))
        idx += length + 1
    return ".".join(names), idx


def parse_answer(data: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, idx = parse_name(data, offset)
    if idx + 10 > len(data):
        raise ValueError("Malformed DNS response: not enough data for answer")

    (atype, aclass, ttl, rdlength) = struct.unpack(">HHIH", data[idx : idx + 10])
    idx += 10

    if idx + rdlength > len(data):
        raise ValueError("Malformed DNS response: RDATA extends beyond packet")

    if atype == 1:  # A Record
        rdata = ".".join(map(str, struct.unpack("BBBB", data[idx : idx + 4])))
    elif atype == 5:  # CNAME Record
        rdata, _ = parse_name(data, idx)
    else:
        rdata = base64.b64encode(data[idx : idx + rdlength]).decode()

    idx += rdlength

    return {
        "name": name,
        "type": atype,
        "class": aclass,
        "ttl": ttl,
        "rdlength": rdlength,
        "rdata": rdata,
    }, idx


def decode_dns_response(
    encoded_response: str,
) -> Dict[str, int | str | List[Dict[str, Any]]]:
    while len(encoded_response) % 4 != 0:
        encoded_response += "="

    decoded_bytes = base64.b64decode(encoded_response)

    if len(decoded_bytes) < 12:
        raise ValueError("Decoded data too short to be a valid DNS response")

    # Parse basic DNS header
    (id, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
        ">HHHHHH", decoded_bytes[:12]
    )

    # Parse question section (assuming one question)
    qname, idx = parse_name(decoded_bytes, 12)

    if idx + 4 > len(decoded_bytes):
        raise ValueError(
            "Malformed DNS response: not enough data for question type and class"
        )

    (qtype, qclass) = struct.unpack(">HH", decoded_bytes[idx : idx + 4])
    idx += 4

    answers = []
    for _ in range(ancount):
        answer, idx = parse_answer(decoded_bytes, idx)
        answers.append(answer)

    result = {
        "id": id,
        "flags": f"{flags:04x}",
        "questions": qdcount,
        "answers": ancount,
        "answerdetail": answers,
        "authority_rrs": nscount,
        "additional_rrs": arcount,
        "qtype": qtype,
        "qclass": qclass,
        "qname": qname,
    }

    return result

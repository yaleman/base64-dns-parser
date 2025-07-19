from base64_dns_parser import decode_dns_response, Response


def test_decoding() -> None:

    # Base64-encoded DNS response
    encoded_response = "DAWBgAABAAYAAAAAB2dzcC1zc2wCbHMFYXBwbGUDY29tAAABAAHADAAFAAEAAA4MACEHZ3NwLXNzbAhscy1hcHBsZQNjb20GYWthZG5zA25ldADAMgAFAAEAAAAaABEOZ3NwLXNzbC1nZW9tYXDAOsBfAAUAAQAAADgACwhnc3B4LXNzbMAUwHwABQABAAAODAATBmdldC1ieAFnB2FhcGxpbWfAHcCTAAEAAQAAABoABBH9Q8bAkwABAAEAAAAaAAQR"

    expected_result = Response.model_validate({
        "id": 3077,
        "flags": "8180",
        "questions": 1,
        "answers": 6,
        "answerdetail": [
            {
                "name": "gsp-ssl.ls.apple.com",
                "type": 5,
                "class": 1,
                "ttl": 3596,
                "rdlength": 33,
                "rdata": "gsp-ssl.ls-apple.com.akadns.net",
            },
            {
                "name": "gsp-ssl.ls-apple.com.akadns.net",
                "type": 5,
                "class": 1,
                "ttl": 26,
                "rdlength": 17,
                "rdata": "gsp-ssl-geomap.ls-apple.com.akadns.net",
            },
            {
                "name": "gsp-ssl-geomap.ls-apple.com.akadns.net",
                "type": 5,
                "class": 1,
                "ttl": 56,
                "rdlength": 11,
                "rdata": "gspx-ssl.ls.apple.com",
            },
            {
                "name": "gspx-ssl.ls.apple.com",
                "type": 5,
                "class": 1,
                "ttl": 3596,
                "rdlength": 19,
                "rdata": "get-bx.g.aaplimg.com",
            },
            {
                "name": "get-bx.g.aaplimg.com",
                "type": 1,
                "class": 1,
                "ttl": 26,
                "rdlength": 4,
                "rdata": "17.253.67.198",
            },

        ],
        "authority_rrs": 0,
        "additional_rrs": 0,
        "qtype": 1,
        "qclass": 1,
        "qname": "gsp-ssl.ls.apple.com",
        "errors": ["Malformed DNS response: RDATA extends beyond packet"]
    })

    assert decode_dns_response(encoded_response) == expected_result

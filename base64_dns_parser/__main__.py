import binascii
import json
import sys

from . import decode_dns_response


def main() -> None:
    if len(sys.argv) == 1:
        print(f"Usage: {sys.argv[0]} [--expand] <base64_dns_response>")
        print(
            "  Pass this a base64-encoded-bytes DNS response and it'll dump it out in JSON format."
        )
        print()
        print("  --expand: Expand the results into individual answers")
        sys.exit(1)
    else:
        try:
            result = decode_dns_response(sys.argv[-1])
        except binascii.Error as error:
            print(f"Error decoding base64: {error}", file=sys.stderr)
            sys.exit(1)
        if "--expand" in sys.argv:
            print("Expanding results", file=sys.stderr)

            answerdetail = result.get("answerdetail", [])
            if isinstance(answerdetail, int):
                raise ValueError("answerdetail is an int, not a list")
            if len(answerdetail) == 0:
                # just dump the result
                print(json.dumps(result))
            else:
                for answer in answerdetail:
                    extended_result = result.copy()
                    extended_result["answerdetail"] = answer  # type: ignore[assignment]
                    print(json.dumps(extended_result))
        else:
            print(json.dumps(result))


if __name__ == "__main__":
    main()

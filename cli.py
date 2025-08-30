#!/usr/bin/env python3
import argparse
import logging
import json

from nr7101.nr7101 import NR7101
from nr7101.version import __version__

RETRY_COUNT = 2


def cli():
    parser = argparse.ArgumentParser(
        description=f"NR7101 status fetcher v{__version__}"
    )
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--cookie", default=".nr7101.cookie")
    parser.add_argument("--no-cookie", action="store_true")
    parser.add_argument(
        "--reboot",
        action="store_true",
        help="Reboot the unit if the connection is down",
    )
    parser.add_argument(
        "--force-reboot",
        action="store_true",
        help="Reboot the unit regardless of the connection status",
    )
    parser.add_argument("url")
    parser.add_argument("username")
    parser.add_argument("password")

    args = parser.parse_args()

    if args.verbose > 0:
        logging.basicConfig(level=logging.DEBUG)
        if args.verbose > 1:
            import http.client
            http.client.HTTPConnection.debuglevel = 1
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    dev = NR7101(args.url, args.username, args.password)

    if not args.no_cookie:
        dev.load_cookies(args.cookie)

    status = None

    for _retry in range(RETRY_COUNT):
        try:
            status = dev.get_status(RETRY_COUNT)
            if status:
                device_info = dev.get_json_object("status")
                if device_info:
                    status["device_info"] = device_info
            if not args.no_cookie:
                dev.store_cookies(args.cookie)
            break
        except (OSError, TimeoutError, ConnectionError):
            if args.verbose > 0:
                print(f"Connection attempt {_retry + 1} failed", file=sys.stderr)

    print(json.dumps(status, indent=2))

    if status is None:
        return 1

    dev.logout()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(cli())

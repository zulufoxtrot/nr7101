#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import logging
import json
import http.client

from .nr7101 import NR7101
from .version import __version__

RETRY_COUNT = 2

logger = logging.getLogger(__name__)


def cli():
    parser = argparse.ArgumentParser(
        description=f"NR7101 status fetcher v{__version__}"
    )
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("url")
    parser.add_argument("username")
    parser.add_argument("password")

    args = parser.parse_args()

    if args.verbose > 0:
        http.client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    router_connection = NR7101(args.url, args.username, args.password)

    if router_connection.login() is None:
        return

    try:
        while True:
            action = input("Enter DAL command, route (starting with /) or 'exit' to quit: ").strip()
            if action.lower() == "exit":
                router_connection.logout()
                break
            if action:
                if action.startswith('/'):
                    response = router_connection.do_request(action)
                    if response is not None:
                        print(json.dumps(response, indent=2))
                    else:
                        print("No response or invalid route.")
                else:
                    try:
                        response = router_connection.get_json_object(action)
                        if response is not None:
                            print(json.dumps(response, indent=2))
                        else:
                            print("No response or invalid command.")
                    except Exception as e:
                        print(f"Error executing command '{action}': {e}")
    except KeyboardInterrupt:
        router_connection.logout()
        return

if __name__ == "__main__":
    import sys

    rc = cli()
    sys.exit(rc)
#!/usr/bin/env python3

# BSD 3-Clause License
#
# Copyright (c) 2023, BISDN GmbH
# All rights reserved.

#
# pylint: disable=W0511
# pylint: disable=C0411
# pylint: disable=R0801
#

""" upsf_server application """

from concurrent import futures
import os
import sys
import random
import signal
import socket
import time
import argparse
import logging
from upsf_server.protos import service_v1_pb2_grpc
from upsf_server.server import SssUpsfServicer
import grpc


def parse_arguments(defaults, loglevels):
    """parse command line arguments"""
    parser = argparse.ArgumentParser(sys.argv[0])

    parser.add_argument(
        "--name",
        help=f"set application name (default: {defaults['name']})",
        dest="name",
        action="store",
        default=defaults["name"],
        type=str,
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        help=f"set log level (default: {defaults['loglevel']})",
        dest="loglevel",
        choices=loglevels.keys(),
        action="store",
        default=defaults["loglevel"],
        type=str,
    )

    parser.add_argument(
        "--max-workers",
        "--grpc-max-workers",
        help="set maximum number of worker threads for gRPC service "
        f"(default: {defaults['grpc_max_workers']})",
        dest="grpc_max_workers",
        action="store",
        default=defaults["grpc_max_workers"],
        type=int,
    )

    parser.add_argument(
        "--bind-addr",
        "--grpc-bind-addr",
        help="set binding transport address for gRPC service "
        f"(default: {defaults['grpc_bind_addr']})",
        dest="grpc_bind_addr",
        action="store",
        default=defaults["grpc_bind_addr"],
        type=str,
    )

    parser.add_argument(
        "--bind-port",
        "--grpc-bind-port",
        help="set binding transport port for gRPC service "
        f"(default: {defaults['grpc_bind_port']})",
        dest="grpc_bind_port",
        action="store",
        default=defaults["grpc_bind_port"],
        type=int,
    )

    parser.add_argument(
        "--redis-host",
        help="set redis host" f"(default: {defaults['redis_host']})",
        dest="redis_host",
        action="store",
        default=defaults["redis_host"],
        type=str,
    )

    parser.add_argument(
        "--redis-port",
        help="set redis port" f"(default: {defaults['redis_port']})",
        dest="redis_port",
        action="store",
        default=defaults["redis_port"],
        type=int,
    )

    parser.add_argument(
        "--redis-password",
        help="set redis password" f"(default: {defaults['redis_password']})",
        dest="redis_password",
        action="store",
        default=defaults["redis_password"],
        type=str,
    )

    parser.add_argument(
        "--redis-health-check-interval",
        help="set redis health check interval"
        f"(default: {defaults['redis_health_check_interval']})",
        dest="redis_health_check_interval",
        action="store",
        default=defaults["redis_health_check_interval"],
        type=int,
    )

    parser.add_argument(
        "--default-shard",
        help="set default shard for new session contexts due to failed sss lookups"
        f"(default: {defaults['default_shard_name']})",
        dest="default_shard_name",
        action="store",
        default=defaults["default_shard_name"],
        type=str,
    )

    parser.add_argument(
        "--upsf-cmd-queue",
        help="set cmd queue to listen and process ingress changes"
        f"(default: {defaults['upsf_cmd_queue']})",
        dest="upsf_cmd_queue",
        action="store",
        default=defaults["upsf_cmd_queue"],
        type=str,
    )

    parser.add_argument(
        "--upsf-cmd-queue-auto-process",
        help="set cmd queue auto processing"
        f"(default: {defaults['upsf_cmd_queue_auto_process']})",
        dest="upsf_cmd_queue_auto_process",
        action="store",
        default=defaults["upsf_cmd_queue_auto_process"],
        type=bool,
    )

    return parser.parse_args(sys.argv[1:])


def main():
    """main function"""
    defaults = {
        # app name
        "name": os.environ.get("NAME", "upsf-server"),
        # loglevel
        "loglevel": os.environ.get("LOGLEVEL", "info"),
        # max workers
        "grpc_max_workers": os.environ.get("GRPC_MAX_WORKERS", 16),
        # insecure server binding address
        "grpc_bind_addr": os.environ.get("GRPC_BIND_ADDR", "[::]"),
        # insecure server binding address
        "grpc_bind_port": os.environ.get("GRPC_BIND_PORT", "50051"),
        # redis host
        "redis_host": os.environ.get("REDIS_HOST", "127.0.0.1"),
        # redis port
        "redis_port": os.environ.get("REDIS_PORT", 6379),
        # redis password
        "redis_password": os.environ.get("REDIS_PASSWORD", None),
        # redis health check interval
        "redis_health_check_interval": os.environ.get(
            "REDIS_HEALTH_CHECK_INTERVAL", 30
        ),
        # default shard to assign to new session context in failed sss lookups
        "default_shard_name": os.environ.get("DEFAULT_SHARD_NAME", "default-shard"),
        "upsf_cmd_queue": os.environ.get("UPSF_CMD_QUEUE", "UpdatesIngress"),
        "upsf_cmd_queue_auto_process": os.environ.get(
            "UPSF_CMD_QUEUE_AUTO_PROCESS", True
        ),
    }

    loglevels = {
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
        "debug": logging.DEBUG,
    }

    args = parse_arguments(defaults, loglevels)

    # configure logging, here: root logger
    log = logging.getLogger("")

    # add StreamHandler
    hnd = logging.StreamHandler()
    formatter = logging.Formatter(
        f"%(asctime)s: [%(levelname)s] host: {socket.gethostname()}, "
        f"process: {args.name}, "
        "module: %(module)s, "
        "func: %(funcName)s, "
        "trace: %(exc_text)s, "
        "message: %(message)s"
    )
    hnd.setFormatter(formatter)
    hnd.setLevel(loglevels[args.loglevel])
    log.addHandler(hnd)

    # set log level of root logger
    log.setLevel(loglevels[args.loglevel])
    # set log level of python requests library
    logging.getLogger("requests").setLevel(loglevels[args.loglevel])
    # set log level of underlying python urllib3 library
    logging.getLogger("urllib3").setLevel(loglevels[args.loglevel])

    terminate = False

    def cleanup(signum, frame):
        nonlocal terminate
        terminate = True
        log.info(
            {
                "entity": "upsf-server",
                "event": "signal",
                "signum": signum,
                "frame": frame,
                "terminate": terminate,
            }
        )

    # install SIGTERM handler
    signal.signal(signal.SIGTERM, cleanup)

    # seed random module
    random.seed(os.urandom(16))

    # set flag do_not_exit_on_failure
    do_not_exit_on_failure = os.environ.get("DO_NOT_EXIT_ON_FAILURE", False)

    # prepare kwargs
    kwargs = vars(args)

    # create gRPC server
    server = grpc.server(
        futures.ThreadPoolExecutor(
            max_workers=args.grpc_max_workers,
        )
    )

    # add gRPC servicer to server
    service_v1_pb2_grpc.add_upsfServicer_to_server(
        SssUpsfServicer(**kwargs),
        server,
    )

    # TODO: exception handling?
    server.add_insecure_port(f"{args.grpc_bind_addr}:{args.grpc_bind_port}")
    server.start()
    server.wait_for_termination()

    if do_not_exit_on_failure:
        while True:
            time.sleep(60)


if __name__ == "__main__":
    main()

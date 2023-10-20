#!/usr/bin/env python3

# BSD 3-Clause License
#
# Copyright (c) 2023, BISDN GmbH
# All rights reserved.

"""module redis_connection"""

#
# pylint: disable=E1101
# pylint: disable=C0103
# pylint: disable=C0209
# pylint: disable=C0301
# pylint: disable=C0302
# pylint: disable=C0411
# pylint: disable=R0801
# pylint: disable=R0904
# pylint: disable=R0912
# pylint: disable=R0914
# pylint: disable=R0915
# pylint: disable=W0631
# pylint: disable=W0703
# pylint: disable=W0511
#

# from concurrent import futures
import os
import uuid
import redis
import logging
import contextlib
import threading
import traceback


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class RedisConnection:
    """class RedisConnection"""

    _defaults = {
        "name": str(uuid.uuid4()),
        "redis_host": os.environ.get("REDIS_HOST", "127.0.0.1"),
        "redis_port": os.environ.get("REDIS_PORT", 6379),
        "redis_password": os.environ.get("REDIS_PASSWORD", None),
        "redis_health_check_interval": os.environ.get(
            "REDIS_HEALTH_CHECK_INTERVAL", 30
        ),
        "loglevel": os.environ.get("LOGLEVEL", "info"),
    }

    _loglevels = {
        "critical": logging.CRITICAL,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "error": logging.ERROR,
        "debug": logging.DEBUG,
    }

    # lock for RedisConnection pool
    _pool_lock = threading.RLock()

    # pool of RedisConnection instances
    _pool = {}

    def __init__(self, **kwargs):
        """__init__"""

        self._redis_conn = None
        self._connected = False

        self.initialize(**kwargs)

    def initialize(self, **kwargs):
        """initialize"""

        # set internal attributes
        for key, value in self._defaults.items():
            setattr(self, key, kwargs.get(key, value))

        # logger
        self._log = logging.getLogger(__name__)
        self._log.setLevel(self._loglevels[self.loglevel])

        # add this to pool
        with self._pool_lock:
            self._pool[self.name] = self

    def __str__(self):
        """return simple descriptive string"""
        return "{}({})".format(
            self.__class__.__name__,
            getattr(self, "name", None),
        )

    def __repr__(self):
        """return descriptive string"""
        return "{}({})".format(
            self.__class__.__name__,
            "".join(
                [
                    "{}={}, ".format(key, getattr(self, key, value))
                    for key, value in self._defaults.items()
                ]
            ),
        )

    @property
    def log(self):
        """return read-only logger"""
        return self._log

    @property
    def rconn(self):
        """return read-only redis connection"""
        return self._redis_conn

    def connect(self):
        """connect"""
        with self._pool_lock:
            while True:
                try:
                    if self._connected is False:
                        with contextlib.suppress(Exception):
                            self.disconnect()
                        self.log.debug(
                            {
                                "entity": self.name,
                                "event": "connect to redis service",
                            }
                        )
                        self._redis_conn = redis.Redis(
                            connection_pool=redis.BlockingConnectionPool(
                                host=self.redis_host,
                                port=self.redis_port,
                                password=self.redis_password,
                                health_check_interval=self.redis_health_check_interval,
                                decode_responses=True,
                            )
                        )
                        self._connected = True
                    return self._redis_conn
                except Exception as error:
                    self.log.error(
                        {
                            "entity": self.name,
                            "event": "failure: connect to redis service",
                            "error": str(error),
                            "traceback": traceback.format_exc(),
                        }
                    )
                    self._redis_conn = None
                    self._connected = False
                    raise

    def disconnect(self):
        """disconnect"""
        with self._pool_lock:
            if self._connected is False:
                return
            self.log.debug(
                {
                    "entity": self.name,
                    "event": "disconnect from redis service",
                }
            )
            self._redis_conn = None
            self._connected = False

    def redis_open(self):
        """get this"""
        return self

    def __enter__(self):
        """PEP343"""
        return self.connect()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """PEP343"""
        if exc_type is not None:
            self.log.error(
                {
                    "entity": str(self),
                    "event": "exception occurred in redis connection, disconnecting for reset",
                    "exc_type": str(exc_type),
                    "exc_value": str(exc_value),
                    "exc_traceback": exc_traceback,
                    "traceback": traceback.format_exc(),
                }
            )
            self.disconnect()


def main():
    """main function"""

    redis_c = RedisConnection(
        redis_host="127.0.0.1",
        redis_port=6379,
        redis_password=None,
        redis_health_check_interval=30,
    )

    with redis_c.redis_open() as rconn:
        rconn.publish("testing", "a test message")


if __name__ == "__main__":
    logging.basicConfig()
    main()

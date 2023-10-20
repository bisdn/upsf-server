#!/usr/bin/env python3

# BSD 3-Clause License
#
# Copyright (c) 2023, BISDN GmbH
# All rights reserved.

"""upsf-server"""

#
# pylint: disable=too-many-return-statements
# pylint: disable=too-many-nested-blocks
# pylint: disable=too-many-statements
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
# pylint: disable=too-many-lines
# pylint: disable=no-name-in-module
# pylint: disable=no-member
#

from concurrent import futures
import os
import threading
import uuid
import logging
import inspect
import contextlib
import datetime
import traceback
import json
import hashlib
import redis
import grpc

from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import MessageToJson
from google.protobuf.wrappers_pb2 import StringValue
from upsf_server.protos.messages_v1_pb2 import (
    Item,
    MetaData,
    Maintenance,
    ServiceGateway,
    ServiceGatewayUserPlane,
    TrafficSteeringFunction,
    Shard,
    NetworkConnection,
    SessionContext,
    SessionFilter,
    L2vpn,
    PortVlan,
    Vtep,
    DerivedState,
)
from upsf_server.protos import service_v1_pb2_grpc
from upsf_server.protos.service_v1_pb2 import (
    ItemType,
    UpdateReq,
)

from upsf_server.redis_connection import (
    RedisConnection,
)


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def bool2str(value):
    """map bool into string"""
    if isinstance(value, (bool,)) and value is True:
        return "true"
    if isinstance(value, (int,)) and value > 0:
        return "true"
    if isinstance(value, (str,)) and value not in ("", None):
        return "true"
    return "false"


def str2bool(value):
    """map string into bool"""
    if value in (
        "1",
        "yes",
        "on",
        "true",
        "True",
        "TRUE",
        "t",
        "T",
    ):
        return True
    return False


def session_hash(session):
    """hashify session context to uniquely identify a session"""
    _hash = hashlib.md5()  # nosec B324 B303
    _hash.update(
        session.circuit_id.encode()
        + session.remote_id.encode()
        + session.session_filter.source_mac_address.encode()
        + str(session.session_filter.svlan).encode()
        + str(session.session_filter.cvlan).encode()
    )
    return _hash.hexdigest()


def snake_case2studly_case(text):
    """convert snake_case to StudlyCase"""
    _str = text.replace("-", " ").replace("_", " ")
    _str = _str.split()
    if len(text) == 0:
        return text
    return "".join(i.capitalize() for i in _str)


def get_transport_endpoint(params):
    """get transport endpoint by endpoint_type"""
    if params in (
        "",
        "{}",
        {},
        None,
    ):
        return None

    if not isinstance(params, (dict,)):
        return None

    if params.get("endpointName", "") in ("", None):
        return None

    if "vtep" in params:
        for param in (
            "ipAddress",
            "udpPort",
            "vni",
        ):
            if param not in params.get("vtep", {}):
                return None
        return NetworkConnection.Spec.Endpoint(
            endpoint_name=params["endpointName"],
            vtep=Vtep(
                ip_address=params["vtep"]["ipAddress"],
                udp_port=int(params["vtep"]["udpPort"]),
                vni=int(params["vtep"]["vni"]),
            ),
        )
    if "l2vpn" in params:
        for param in ("vpnId",):
            if param not in params.get("l2vpn", {}):
                return None
        return NetworkConnection.Spec.Endpoint(
            endpoint_name=params["endpointName"],
            l2vpn=L2vpn(
                vpn_id=int(params["l2vpn"]["vpnId"]),
            ),
        )
    if "portVlan" in params:
        for param in (
            "logicalPort",
            "svlan",
            "cvlan",
        ):
            if param not in params.get("portVlan", {}):
                return None
        return NetworkConnection.Spec.Endpoint(
            endpoint_name=params["endpointName"],
            port_vlan=PortVlan(
                logical_port=params["portVlan"]["logicalPort"],
                svlan=int(params["portVlan"]["svlan"]),
                cvlan=int(params["portVlan"]["cvlan"]),
            ),
        )
    raise TypeError(f"Invalid Type in Object {params}")


def get_endpoint_spec(item):
    """get endpoint spec"""
    nc_spec_type = item.spec.WhichOneof("nc_spec")
    if nc_spec_type is None:
        return None
    if nc_spec_type in ("SsPtpSpec", "ss_ptp"):
        return item.spec.ss_ptp

    if nc_spec_type in ("SsMptpSpec", "ss_mptpc"):
        return item.spec.ss_mptpc

    if nc_spec_type in ("MsPtpSpec", "ms_ptp"):
        return item.spec.ms_ptp

    if nc_spec_type in ("MsMptpSpec", "ms_mptp"):
        return item.spec.ms_mptp

    raise TypeError(f"Invalid Type {item['nc_spec_type']}")


def get_nc_spec(params):
    """get nc_spec by type"""
    if params.get("nc_spec_type", None) in (
        "",
        None,
    ):
        return None
    if params["nc_spec_type"] in ("SsPtpSpec", "ss_ptp"):
        netconn = NetworkConnection.Spec.SsPtpSpec(
            tsf_endpoint=get_transport_endpoint(
                json.loads(params.get("tsf_endpoints", "{}"))
            ),
        )
        for endpoint in params["sgup_endpoints"].split(",,"):
            if endpoint not in (
                "",
                None,
            ):
                netconn.sgup_endpoint.append(
                    get_transport_endpoint(json.loads(endpoint))
                )
        return NetworkConnection.Spec(
            maximum_supported_quality=int(params["maximum_supported_quality"]),
            ss_ptp=netconn,
        )

    if params["nc_spec_type"] in ("SsMptpSpec", "ss_mptpc"):
        netconn = NetworkConnection.Spec.SsMptpSpec()
        for endpoint in params["sgup_endpoints"].split(",,"):
            if endpoint not in (
                "",
                None,
            ):
                netconn.sgup_endpoint.append(
                    get_transport_endpoint(json.loads(endpoint))
                )
        for endpoint in params["tsf_endpoints"].split(",,"):
            if endpoint not in (
                "",
                None,
            ):
                netconn.tsf_endpoint.append(
                    get_transport_endpoint(json.loads(endpoint))
                )
        return NetworkConnection.Spec(
            maximum_supported_quality=int(params["maximum_supported_quality"]),
            ss_mptpc=netconn,
        )

    if params["nc_spec_type"] in ("MsPtpSpec", "ms_ptp"):
        return NetworkConnection.Spec(
            maximum_supported_quality=int(params["maximum_supported_quality"]),
            ms_ptp=NetworkConnection.Spec.MsPtpSpec(
                sgup_endpoint=get_transport_endpoint(
                    json.loads(params.get("sgup_endpoints", "{}"))
                ),
                tsf_endpoint=get_transport_endpoint(
                    json.loads(params.get("tsf_endpoints", "{}"))
                ),
            ),
        )

    if params["nc_spec_type"] in ("MsMptpSpec", "ms_mptp"):
        netconn = NetworkConnection.Spec.MsMptpSpec(
            sgup_endpoint=get_transport_endpoint(
                json.loads(params.get("sgup_endpoints", "{}"))
            ),
        )
        for endpoint in params["tsf_endpoints"].split(",,"):
            if endpoint not in (
                "",
                None,
            ):
                netconn.tsf_endpoint.append(
                    get_transport_endpoint(json.loads(endpoint))
                )
        return NetworkConnection.Spec(
            maximum_supported_quality=int(params["maximum_supported_quality"]),
            ms_mptp=netconn,
        )

    raise TypeError(f"Invalid Type {params['nc_spec_type']}")


def fill_item(item_type, mapping):
    """fill item with mapping data derived by item_type"""
    _timestamp = Timestamp()
    _timestamp.FromDatetime(
        datetime.datetime.utcfromtimestamp(
            float(mapping.get("created", datetime.datetime.utcnow().timestamp()))
        )
    )
    _timestamp2 = Timestamp()
    _timestamp2.FromDatetime(
        datetime.datetime.utcfromtimestamp(
            float(mapping.get("last_updated", datetime.datetime.utcnow().timestamp()))
        )
    )
    created = _timestamp
    last_updated = _timestamp2
    if item_type in ("network_connection, NetworkConnection"):
        return Item(
            network_connection=NetworkConnection(
                name=mapping.get("name"),
                metadata=MetaData(
                    description=mapping.get("description", ""),
                    created=created,
                    last_updated=last_updated,
                    derived_state=mapping.get("derived_state", "unknown"),
                ),
                maintenance=Maintenance(
                    maintenance_req=Maintenance.MaintenanceReq.Value(
                        mapping.get("maintenance", "none")
                    ),
                ),
                spec=get_nc_spec(mapping),
                status=NetworkConnection.Status(
                    nc_active={
                        value.split(":")[0]: str2bool(value.split(":")[1])
                        for value in mapping.get("nc_active", "").split(",")
                        if value
                    },
                    allocated_shards=int(mapping.get("allocated_shards", 0)),
                ),
            )
        )

    if item_type in ("traffic_steering_function", "TrafficSteeringFunction"):
        return Item(
            traffic_steering_function=TrafficSteeringFunction(
                name=mapping.get("name"),
                metadata=MetaData(
                    description=mapping.get("description", ""),
                    created=created,
                    last_updated=last_updated,
                    derived_state=mapping.get("derived_state", "unknown"),
                ),
                spec=TrafficSteeringFunction.Spec(
                    default_endpoint=get_transport_endpoint(
                        json.loads(mapping.get("default_endpoint", "{}"))
                    ),
                ),
            )
        )

    if item_type in ("service_gateway", "ServiceGateway"):
        return Item(
            service_gateway=ServiceGateway(
                name=mapping.get("name"),
                metadata=MetaData(
                    description=mapping.get("description", ""),
                    created=created,
                    last_updated=last_updated,
                    derived_state=mapping.get("derived_state", "unknown"),
                ),
            )
        )

    if item_type in ("service_gateway_user_plane", "ServiceGatewayUserPlane"):
        return Item(
            service_gateway_user_plane=ServiceGatewayUserPlane(
                service_gateway_name=mapping.get("service_gateway_name"),
                name=mapping.get("name"),
                metadata=MetaData(
                    description=mapping.get("description", ""),
                    created=created,
                    last_updated=last_updated,
                    derived_state=mapping.get("derived_state", "unknown"),
                ),
                maintenance=Maintenance(
                    maintenance_req=Maintenance.MaintenanceReq.Value(
                        mapping.get("maintenance", "none")
                    ),
                ),
                spec=ServiceGatewayUserPlane.Spec(
                    max_session_count=int(mapping.get("max_session_count", 0)),
                    max_shards=int(mapping.get("max_shards", 0)),
                    supported_service_group=mapping.get(
                        "supported_service_group", ""
                    ).split(","),
                    default_endpoint=get_transport_endpoint(
                        json.loads(mapping.get("default_endpoint", "{}"))
                    ),
                ),
                status=ServiceGatewayUserPlane.Status(
                    allocated_session_count=int(
                        mapping.get("allocated_session_count", 0)
                    ),
                    allocated_shards=int(mapping.get("allocated_shards", 0)),
                ),
            )
        )

    if item_type in ("session_context", "SessionContext"):
        return Item(
            session_context=SessionContext(
                name=mapping.get("name"),
                metadata=MetaData(
                    description=mapping.get("description", ""),
                    created=created,
                    last_updated=last_updated,
                    derived_state=mapping.get("derived_state", "unknown"),
                ),
                spec=SessionContext.Spec(
                    traffic_steering_function=mapping.get(
                        "traffic_steering_function", ""
                    ),
                    required_service_group=mapping.get(
                        "required_service_group", ""
                    ).split(","),
                    required_quality=int(mapping.get("required_quality", 0)),
                    circuit_id=mapping.get("circuit_id", ""),
                    remote_id=mapping.get("remote_id", ""),
                    session_filter=SessionFilter(
                        source_mac_address=mapping.get("source_mac_address"),
                        svlan=int(mapping.get("s_tag", 0)),
                        cvlan=int(mapping.get("c_tag", 0)),
                    ),
                    desired_state=SessionContext.Spec.DesiredState(
                        shard=mapping.get("desired_shard", ""),
                    ),
                ),
                status=SessionContext.Status(
                    current_state=SessionContext.Status.CurrentState(
                        user_plane_shard=mapping.get("user_plane_shard", ""),
                        tsf_shard=mapping.get("tsf_shard", ""),
                    ),
                ),
            )
        )

    if item_type in ("shard", "Shard"):
        return Item(
            shard=Shard(
                name=mapping.get("name"),
                metadata=MetaData(
                    description=mapping.get("description", ""),
                    created=created,
                    last_updated=last_updated,
                    derived_state=mapping.get("derived_state", "unknown"),
                ),
                spec=Shard.Spec(
                    max_session_count=int(mapping.get("max_session_count", 0)),
                    virtual_mac=mapping.get("virtual_mac"),
                    desired_state=Shard.Spec.DesiredState(
                        service_gateway_user_plane=mapping.get(
                            "desired_service_gateway_user_plane"
                        ),
                        network_connection=mapping.get(
                            "desired_network_connection", ""
                        ).split(","),
                    ),
                    prefix=mapping.get("prefix", "").split(","),
                ),
                status=Shard.Status(
                    allocated_session_count=int(
                        mapping.get("allocated_session_count", 0)
                    ),
                    service_groups_supported=mapping.get(
                        "service_groups_supported", ""
                    ).split(","),
                    current_state=Shard.Status.CurrentState(
                        service_gateway_user_plane=mapping.get(
                            "current_service_gateway_user_plane"
                        ),
                        tsf_network_connection=dict(
                            elem.split(":")
                            for elem in mapping.get(
                                "current_tsf_network_connection", ""
                            ).split(",")
                            if elem
                            not in (
                                "",
                                None,
                            )
                        ),
                    ),
                ),
                mbb=Shard.Mbb(
                    mbb_state=Shard.Mbb.MbbState.Value(
                        mapping.get("mbb_state", "non_mbb_move_requried")
                    ),
                ),
            )
        )
    return Item()


class SssUpsfServicer(service_v1_pb2_grpc.upsfServicer):
    """Provides methods that implement functionality of upsf_server server."""

    _defaults = {
        "name": str(uuid.uuid4()),
        "grpc_max_workers": os.environ.get("GRPC_MAX_WORKERS", 16),
        "loglevel": os.environ.get("LOGLEVEL", "info"),
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

    _loglevels = {
        "critical": logging.CRITICAL,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "error": logging.ERROR,
        "debug": logging.DEBUG,
    }

    def __init__(self, **kwargs):
        """initializer"""

        # set internal attributes
        for key, value in self._defaults.items():
            setattr(self, key, getattr(self, key, kwargs.get(key, value)))

        # logger
        self._log = logging.getLogger(self.__class__.__name__)
        self._log.setLevel(self._loglevels[self.loglevel])

        self.log.info(
            {
                "entity": repr(self),
                "event": "gRPC service initializing...",
            }
        )

        # create new RedisConnection
        self._redis_conn = RedisConnection(**kwargs)

        # create new RedisConnection
        self._redis_cmdq_conn = RedisConnection(**kwargs)

        self._upsf_cmd_queue = None
        if self.upsf_cmd_queue_auto_process:
            self._upsf_cmd_queue = threading.Thread(
                target=SssUpsfServicer.subscribe_to_queue,
                kwargs={
                    "entity": self,
                    "command_queue": self.upsf_cmd_queue,
                },
                daemon=True,
            )
            self._upsf_cmd_queue.start()

        self.log.info(
            {
                "entity": str(self),
                "event": "gRPC service ready.",
            }
        )

    def __str__(self):
        """return simple string"""
        return f"{self.__class__.__name__}()"

    def __repr__(self):
        """return descriptive string"""
        _attributes = "".join(
            [
                f"{key}={getattr(self, key, None)}, "
                for key, value in self._defaults.items()
            ]
        )
        return f"{self.__class__.__name__}({_attributes})"

    @property
    def log(self):
        """return read-only logger"""
        return self._log

    def redis_open(self):
        """get this"""
        return self

    def __enter__(self):
        """PEP343"""
        return self._redis_conn.connect()

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """PEP343"""
        if exc_type is not None:
            self.log.error(
                {
                    "entity": str(self),
                    "event": "exception occurred in redis connection, disconnecting for reset",
                    "exc_type": exc_type,
                    "exc_value": exc_value,
                    "exc_traceback": exc_traceback,
                    "traceback": traceback.format_exc(),
                }
            )
            self._redis_conn.disconnect()

    @staticmethod
    def subscribe_to_queue(**kwargs):
        """redis cmd queue background task"""
        if kwargs.get("entity", None) is None:
            return
        kwargs["entity"].log.debug(
            {
                "event": inspect.currentframe().f_code.co_name,
                "kwargs": kwargs,
            }
        )
        try:
            # pylint: disable=protected-access
            rconn = kwargs["entity"]._redis_cmdq_conn.connect()
            while True:
                with contextlib.suppress(RuntimeError):
                    _, command = rconn.blpop(
                        kwargs.get("command_queue", "UpdatesIngress")
                    )
                    command_dict = json.loads(command)
                    if "cmd" not in command_dict:
                        continue
                    if "type" not in command_dict:
                        continue
                    if "name" not in command_dict:
                        continue

                    _redis_key_egress = None
                    _redis_key_ingress = None
                    if command_dict["type"] in ("service_gateway",):
                        _redis_key_egress = f"/egress/sg/{command_dict['name']}"
                        _redis_key_ingress = f"/ingress/sg/{command_dict['name']}"
                    elif command_dict["type"] in ("service_gateway_user_plane",):
                        _redis_key_egress = f"/egress/up/{command_dict['name']}"
                        _redis_key_ingress = f"/ingress/up/{command_dict['name']}"
                    elif command_dict["type"] in ("traffic_steering_function",):
                        _redis_key_egress = f"/egress/tsf/{command_dict['name']}"
                        _redis_key_ingress = f"/ingress/tsf/{command_dict['name']}"
                    elif command_dict["type"] in ("network_connection",):
                        _redis_key_egress = f"/egress/nc/{command_dict['name']}"
                        _redis_key_ingress = f"/ingress/nc/{command_dict['name']}"
                    elif command_dict["type"] in ("session_context",):
                        _redis_key_egress = f"/egress/ct/{command_dict['name']}"
                        _redis_key_ingress = f"/ingress/ct/{command_dict['name']}"
                    elif command_dict["type"] in ("shard",):
                        _redis_key_egress = f"/egress/sh/{command_dict['name']}"
                        _redis_key_ingress = f"/ingress/sh/{command_dict['name']}"
                    else:
                        continue
                        # raise Exception("Item type not provided")
                    if not rconn.exists(_redis_key_ingress) and command_dict[
                        "cmd"
                    ] not in ("delete",):
                        kwargs["entity"].log.warning(
                            {
                                "entity": str(kwargs["entity"]),
                                "event": "item doesn't exists, requeuing command",
                                "redis_key": _redis_key_ingress,
                                "command": command,
                            }
                        )
                        rconn.publish("UpdatesIngress", command)
                        continue
                    if command_dict["cmd"] in ("delete",):
                        rconn.delete(_redis_key_egress)
                        rconn.srem(
                            f"{snake_case2studly_case(command_dict['type'])}Set",
                            command_dict["name"],
                        )
                        kwargs["entity"].log.debug(
                            {
                                "entity": str(kwargs["entity"]),
                                "event": "delete item stored in redis cache",
                                "redis_key": _redis_key_egress,
                                "name": command_dict["name"],
                            }
                        )
                        continue

                    mapping = rconn.hgetall(_redis_key_ingress)

                    kwargs["entity"].log.debug(
                        {
                            "entity": str(kwargs["entity"]),
                            "event": "item stored in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key_egress, mapping=mapping)

                    # store Name in {type}Set
                    rconn.sadd(
                        f"{snake_case2studly_case(command_dict['type'])}Set",
                        command_dict["name"],
                    )
                    rconn.publish("UpdatesEgress", command)

        except redis.exceptions.ConnectionError as error:
            kwargs["entity"].log.error(
                {
                    "entity": str(kwargs["entity"]),
                    "event": "redis connection failed",
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
            )

    def CreateV1(self, request, context):
        """create"""
        self.log.debug(
            {
                "event": inspect.currentframe().f_code.co_name,
                "request": str(request),
            }
        )

        try:
            with self.redis_open() as rconn:
                # search for item by name if specified
                item_name = None

                # raise error when item is none
                if request.WhichOneof("sssitem") is None:
                    self.log.error(
                        {
                            "entity": str(self),
                            "function": "CreateV1",
                            "event": "Item must be Provided",
                        }
                    )
                    return Item()

                item_type = request.WhichOneof("sssitem")
                item = getattr(request, item_type)

                # raise error when name is empty
                if item.name in ("",):
                    self.log.error(
                        {
                            "entity": str(self),
                            "function": "CreateV1",
                            "event": "Item name not Provided",
                        }
                    )
                    return Item()

                # get item_name
                item_name = item.name
                _timestamp = Timestamp()
                _timestamp.FromDatetime(datetime.datetime.utcnow())

                mapping = {
                    "name": item_name,
                    "description": item.metadata.description,
                    "derived_state": DerivedState.Name(item.metadata.derived_state),
                    "created": _timestamp.ToDatetime().timestamp(),
                    "last_updated": _timestamp.ToDatetime().timestamp(),
                }

                if item_type == "network_connection":
                    # redis key for item
                    _redis_key = f"/ingress/nc/{item_name}"

                    # raise error when item exists
                    item_exists = rconn.exists(_redis_key)
                    if item_exists:
                        self.log.error(
                            {
                                "entity": str(self),
                                "function": "CreateV1",
                                "item.type": "network_connection",
                                "item.name": item_name,
                                "event": "Item exists",
                            }
                        )
                        return Item()

                    nc_spec = get_endpoint_spec(item)
                    nc_spec_type = item.spec.WhichOneof("nc_spec")
                    sgup_endpoints = ""
                    tsf_endpoints = ""
                    if nc_spec not in (
                        "",
                        None,
                    ):
                        if nc_spec_type in (
                            "MsMptpSpec",
                            "MsPtpSpec",
                            "ms_ptp",
                            "ms_mptp",
                        ):
                            if nc_spec.sgup_endpoint not in ("", "[]", [], None):
                                sgup_endpoints = MessageToJson(
                                    nc_spec.sgup_endpoint,
                                    including_default_value_fields=True,
                                )
                        else:
                            if len(nc_spec.sgup_endpoint) > 0:
                                sgup_endpoints = ",,".join(
                                    [
                                        MessageToJson(
                                            ep, including_default_value_fields=True
                                        )
                                        for ep in nc_spec.sgup_endpoint
                                    ]
                                )
                        if nc_spec_type in (
                            "SsPtpSpec",
                            "MsPtpSpec",
                            "ss_ptp",
                            "ms_ptp",
                        ):
                            if nc_spec.tsf_endpoint not in ("", "[]", [], None):
                                tsf_endpoints = MessageToJson(
                                    nc_spec.tsf_endpoint,
                                    including_default_value_fields=True,
                                )
                        else:
                            if len(nc_spec.tsf_endpoint) > 0:
                                tsf_endpoints = ",,".join(
                                    [
                                        MessageToJson(
                                            ep, including_default_value_fields=True
                                        )
                                        for ep in nc_spec.tsf_endpoint
                                    ]
                                )
                    else:
                        nc_spec_type = ""

                    mapping.update(
                        {
                            "maintenance": Maintenance.MaintenanceReq.Name(
                                item.maintenance.maintenance_req
                            ),
                            "maximum_supported_quality": int(
                                item.spec.maximum_supported_quality
                            ),
                            "sgup_endpoints": sgup_endpoints,
                            "tsf_endpoints": tsf_endpoints,
                            "nc_active": ",".join(
                                {
                                    f"{key}:{value}"
                                    for key, value in item.status.nc_active.items()
                                }
                            ),
                            "nc_spec_type": nc_spec_type,
                            "allocated_shards": item.status.allocated_shards,
                        }
                    )

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "creating item in redis cache",
                            "redis_key": _redis_key,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send update notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "create", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                if item_type == "traffic_steering_function":
                    # redis key for item
                    _redis_key = f"/ingress/tsf/{item_name}"

                    # raise error when item exists
                    item_exists = rconn.exists(_redis_key)
                    if item_exists:
                        self.log.error(
                            {
                                "entity": str(self),
                                "function": "CreateV1",
                                "item.type": "traffic_steering_function",
                                "item.name": item_name,
                                "event": "Item exists",
                            }
                        )
                        return Item()

                    mapping.update(
                        {
                            "default_endpoint": MessageToJson(
                                item.spec.default_endpoint,
                                including_default_value_fields=True,
                            ),
                        }
                    )

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "creating item in redis cache",
                            "redis_key": _redis_key,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key, mapping=mapping)

                    # store Name in {item_type}Set (i.e. ServiceGatewaySet)
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "create", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                if item_type == "service_gateway":
                    # redis key for item
                    _redis_key = f"/ingress/sg/{item_name}"

                    # raise error when item exists
                    item_exists = rconn.exists(_redis_key)
                    if item_exists:
                        self.log.error(
                            {
                                "entity": str(self),
                                "function": "CreateV1",
                                "item.type": "service_gateway",
                                "item.name": item_name,
                                "event": "Item exists",
                            }
                        )
                        return Item()

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "creating item in redis cache",
                            "redis_key": _redis_key,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "create", "type": item_type, "name": item_name}
                        ),
                    )
                    return fill_item(item_type, mapping)

                if item_type == "service_gateway_user_plane":
                    # redis key for item
                    _redis_key = f"/ingress/up/{item_name}"

                    # raise error when item exists
                    item_exists = rconn.exists(_redis_key)
                    if item_exists:
                        self.log.error(
                            {
                                "entity": str(self),
                                "function": "CreateV1",
                                "item.type": "service_gateway_user_plane",
                                "item.name": item_name,
                                "event": "Item exists",
                            }
                        )
                        return Item()

                    mapping.update(
                        {
                            "service_gateway_name": item.service_gateway_name,
                            "max_session_count": int(item.spec.max_session_count),
                            "supported_service_group": ",".join(
                                ssg for ssg in item.spec.supported_service_group
                            ),
                            "maintenance": Maintenance.MaintenanceReq.Name(
                                item.maintenance.maintenance_req
                            ),
                            "allocated_session_count": int(
                                item.status.allocated_session_count
                            ),
                            "allocated_shards": int(item.status.allocated_shards),
                            "max_shards": int(item.spec.max_shards),
                            "default_endpoint": MessageToJson(
                                item.spec.default_endpoint,
                                including_default_value_fields=True,
                            ),
                        }
                    )

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "creating item in redis cache",
                            "redis_key": _redis_key,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "create", "type": item_type, "name": item_name}
                        ),
                    )
                    sssitem = fill_item(item_type, mapping)
                    return sssitem

                if item_type == "session_context":
                    # redis key for item
                    _redis_key = f"/ingress/ct/{item_name}"

                    # raise error when item exists
                    item_exists = rconn.exists(_redis_key)
                    if item_exists:
                        self.log.error(
                            {
                                "entity": str(self),
                                "function": "CreateV1",
                                "item.type": "session_context",
                                "item.name": item_name,
                                "event": "Item exists",
                            }
                        )
                        return Item()

                    mapping.update(
                        {
                            "traffic_steering_function": item.spec.traffic_steering_function,
                            "required_service_group": ",".join(
                                [
                                    rsg
                                    for rsg in item.spec.required_service_group
                                    if rsg not in ("",)
                                ]
                            ),
                            "required_quality": item.spec.required_quality,
                            "source_mac_address": item.spec.session_filter.source_mac_address,
                            "s_tag": item.spec.session_filter.svlan,
                            "c_tag": item.spec.session_filter.cvlan,
                            "circuit_id": item.spec.circuit_id,
                            "remote_id": item.spec.remote_id,
                            "desired_shard": item.spec.desired_state.shard,
                            "user_plane_shard": item.status.current_state.user_plane_shard,
                            "tsf_shard": item.status.current_state.tsf_shard,
                        }
                    )

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "creating item in redis cache",
                            "redis_key": _redis_key,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "create", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                if item_type == "shard":
                    # redis key for item
                    _redis_key = f"/ingress/sh/{item_name}"

                    # raise error when item exists
                    item_exists = rconn.exists(_redis_key)
                    if item_exists:
                        self.log.error(
                            {
                                "entity": str(self),
                                "function": "CreateV1",
                                "item.type": "shard",
                                "item.name": item_name,
                                "event": "Item exists",
                            }
                        )
                        return Item()
                    desired_sgups = item.spec.desired_state.service_gateway_user_plane
                    current_sgups = item.status.current_state.service_gateway_user_plane
                    current_tsf_items = (
                        item.status.current_state.tsf_network_connection.items()
                    )
                    mapping.update(
                        {
                            "max_session_count": item.spec.max_session_count,
                            "virtual_mac": item.spec.virtual_mac,
                            "desired_service_gateway_user_plane": desired_sgups,
                            "desired_network_connection": ",".join(
                                nc
                                for nc in item.spec.desired_state.network_connection
                                if nc not in ("",)
                            ),
                            "prefix": ",".join(
                                prfx for prfx in item.spec.prefix if prfx not in ("",)
                            ),
                            "allocated_session_count": item.status.allocated_session_count,
                            "current_service_gateway_user_plane": current_sgups,
                            "current_tsf_network_connection": ",".join(
                                {f"{key}:{value}" for key, value in current_tsf_items}
                            ),
                            "mbb_state": Shard.Mbb.MbbState.Name(item.mbb.mbb_state),
                            "service_groups_supported": ",".join(
                                sgs
                                for sgs in item.status.service_groups_supported
                                if sgs not in ("",)
                            ),
                        }
                    )

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "creating item in redis cache",
                            "redis_key": _redis_key,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "create", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                # Return Error when Item Type is Unknown
                self.log.error(
                    {
                        "entity": str(self),
                        "function": "CreateV1",
                        "event": f"Wrong Item Type: {item_type}",
                    }
                )
                return Item()

        except redis.exceptions.ConnectionError as error:
            self.log.error(
                {
                    "entity": str(self),
                    "event": "redis connection failed",
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
            )
            return Item()

    def UpdateV1(self, request, context):
        """update"""
        self.log.debug(
            {
                "event": inspect.currentframe().f_code.co_name,
                "request": str(request),
            }
        )
        try:
            with self.redis_open() as rconn:
                # search for item by name if specified
                item_name = None

                # raise error when item is none
                if request.item.WhichOneof("sssitem") is None:
                    self.log.error(
                        {
                            "entity": str(self),
                            "function": "UpdateV1",
                            "event": "Item must be Provided",
                        }
                    )
                    return Item()

                item_type = request.item.WhichOneof("sssitem")
                item = getattr(request.item, item_type)
                item_name = item.name
                list_merge_strategy = UpdateReq.UpdateOptions.ListMergeStrategy.Name(
                    request.update_options.list_merge_strategy
                )
                if list_merge_strategy not in ("union", "replace", "subtract"):
                    # Return Error when list merge strategy is Unknown
                    self.log.error(
                        {
                            "entity": str(self),
                            "function": "UpdateV1",
                            "event": f"Wrong list merge strategy Type: {list_merge_strategy}",
                        }
                    )
                    raise ValueError(
                        f"Wrong list merge strategy Type: {list_merge_strategy}"
                    )

                # raise error when name is empty
                if item.name in ("",):
                    self.log.error(
                        {
                            "entity": str(self),
                            "function": "UpdateV1",
                            "event": "Item name not provided",
                        }
                    )
                    raise ValueError("Item name not provided")

                # redis key for item
                if item_type in ("service_gateway",):
                    _redis_key_ingress = f"/ingress/sg/{item.name}"
                    _redis_key_egress = f"/egress/sg/{item.name}"
                elif item_type in ("service_gateway_user_plane",):
                    _redis_key_ingress = f"/ingress/up/{item.name}"
                    _redis_key_egress = f"/egress/up/{item.name}"
                elif item_type in ("traffic_steering_function",):
                    _redis_key_ingress = f"/ingress/tsf/{item.name}"
                    _redis_key_egress = f"/egress/tsf/{item.name}"
                elif item_type in ("network_connection",):
                    _redis_key_ingress = f"/ingress/nc/{item.name}"
                    _redis_key_egress = f"/egress/nc/{item.name}"
                elif item_type in ("session_context",):
                    _redis_key_ingress = f"/ingress/ct/{item.name}"
                    _redis_key_egress = f"/egress/ct/{item.name}"
                elif item_type in ("shard",):
                    _redis_key_ingress = f"/ingress/sh/{item.name}"
                    _redis_key_egress = f"/egress/sh/{item.name}"
                else:
                    raise ValueError("Item type not provided")

                # raise error when item exists and update it not true
                if not rconn.exists(_redis_key_ingress) and not rconn.exists(
                    _redis_key_egress
                ):
                    self.log.error(
                        {
                            "entity": str(self),
                            "function": "UpdateV1",
                            "item.type": item_type,
                            "item.name": item.name,
                            "event": f"Item {item.name} doesn't exist",
                        }
                    )
                    raise ValueError(f"Item {item.name} doesn't exist")

                # read egress redis key if it exists
                if rconn.exists(_redis_key_egress):
                    mapping = rconn.hgetall(_redis_key_egress)
                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "item stored in redis cache",
                            "redis_key": _redis_key_egress,
                            "mapping": mapping,
                        }
                    )

                # read ingress redis key if it exists
                if rconn.exists(_redis_key_ingress):
                    mapping = rconn.hgetall(_redis_key_ingress)
                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "item stored in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                # get item_name
                item_name = item.name
                _timestamp = Timestamp()
                _timestamp.FromDatetime(datetime.datetime.utcnow())

                if list_merge_strategy in (
                    "union",
                    "replace",
                ):
                    if item.metadata.description not in ("",):
                        mapping.update({"description": item.metadata.description})

                mapping.update(
                    {
                        "last_updated": _timestamp.ToDatetime().timestamp(),
                    }
                )

                if item_type == "network_connection":
                    if list_merge_strategy in ("union", "replace"):
                        if Maintenance.MaintenanceReq.Name(
                            item.maintenance.maintenance_req
                        ) not in ("",):
                            mapping.update(
                                {
                                    "maintenance": Maintenance.MaintenanceReq.Name(
                                        item.maintenance.maintenance_req
                                    ),
                                }
                            )

                        if item.spec.maximum_supported_quality not in (0,):
                            mapping.update(
                                {
                                    "maximum_supported_quality": int(
                                        item.spec.maximum_supported_quality
                                    ),
                                }
                            )

                    if list_merge_strategy in ("union",):
                        if item.spec.WhichOneof("nc_spec") not in ("", None):
                            nc_spec = get_endpoint_spec(item)

                            nc_spec_type = item.spec.WhichOneof("nc_spec")
                            mapping.update(
                                {
                                    "nc_spec_type": nc_spec_type,
                                }
                            )
                            if nc_spec_type in (
                                "MsMptpSpec",
                                "MsPtpSpec",
                                "ms_ptp",
                                "ms_mptp",
                            ):
                                if MessageToJson(
                                    nc_spec.sgup_endpoint,
                                    including_default_value_fields=True,
                                ) not in (
                                    "",
                                    "{}",
                                    {},
                                    None,
                                ):
                                    mapping.update(
                                        {
                                            "sgup_endpoints": MessageToJson(
                                                nc_spec.sgup_endpoint,
                                                including_default_value_fields=True,
                                            )
                                        }
                                    )

                            else:
                                if f"{nc_spec.sgup_endpoint}" not in (
                                    "",
                                    "[]",
                                    [],
                                    None,
                                ):
                                    sgup_endpoints = ",,".join(
                                        [
                                            MessageToJson(
                                                ep, including_default_value_fields=True
                                            )
                                            for ep in nc_spec.sgup_endpoint
                                        ]
                                    )
                                    if mapping.get("sgup_endpoints") not in (
                                        "",
                                        "{}",
                                        {},
                                        None,
                                    ):
                                        updated_sgup_endpoints = mapping.get(
                                            "sgup_endpoints"
                                        ).split(",,")
                                        new_endpoints = sgup_endpoints.split(",,")
                                        for _endpoint in new_endpoints:
                                            for present_ep in updated_sgup_endpoints:
                                                if (
                                                    json.loads(_endpoint)[
                                                        "endpointName"
                                                    ]
                                                    in json.loads(present_ep)[
                                                        "endpointName"
                                                    ]
                                                ):
                                                    updated_sgup_endpoints.remove(
                                                        present_ep
                                                    )
                                        updated_sgup_endpoints.extend(new_endpoints)
                                        sgup_endpoints = ",,".join(
                                            updated_sgup_endpoints
                                        )

                                    mapping.update({"sgup_endpoints": sgup_endpoints})

                            if nc_spec_type in (
                                "SsPtpSpec",
                                "MsPtpSpec",
                                "ss_ptp",
                                "ms_ptp",
                            ):
                                if MessageToJson(
                                    nc_spec.tsf_endpoint,
                                    including_default_value_fields=True,
                                ) not in (
                                    "",
                                    "{}",
                                    {},
                                    None,
                                ):
                                    mapping.update(
                                        {
                                            "tsf_endpoints": MessageToJson(
                                                nc_spec.tsf_endpoint,
                                                including_default_value_fields=True,
                                            )
                                        }
                                    )

                            else:
                                if f"{nc_spec.tsf_endpoint}" not in (
                                    "",
                                    "[]",
                                    [],
                                    None,
                                ):
                                    tsf_endpoints = ",,".join(
                                        [
                                            MessageToJson(
                                                ep, including_default_value_fields=True
                                            )
                                            for ep in nc_spec.tsf_endpoint
                                        ]
                                    )
                                    if mapping.get("tsf_endpoints") not in (
                                        "",
                                        "{}",
                                        {},
                                        None,
                                    ):
                                        updated_tsf_endpoints = mapping.get(
                                            "tsf_endpoints"
                                        ).split(",,")
                                        new_endpoints = tsf_endpoints.split(",,")
                                        for _endpoint in new_endpoints:
                                            for present_ep in updated_tsf_endpoints:
                                                if (
                                                    json.loads(_endpoint)[
                                                        "endpointName"
                                                    ]
                                                    in json.loads(present_ep)[
                                                        "endpointName"
                                                    ]
                                                ):
                                                    updated_tsf_endpoints.remove(
                                                        present_ep
                                                    )
                                        updated_tsf_endpoints.extend(new_endpoints)
                                        tsf_endpoints = ",,".join(
                                            updated_tsf_endpoints,
                                        )

                                    mapping.update({"tsf_endpoints": tsf_endpoints})
                        if item.status.nc_active not in (
                            "",
                            "{}",
                            {},
                        ):
                            nc_active = ",".join(
                                {
                                    f"{key}:{value}"
                                    for key, value in item.status.nc_active.items()
                                }
                            )
                            if mapping.get("nc_active") not in (
                                "",
                                "{}",
                                {},
                            ):
                                updated_nc_active = mapping.get("nc_active").split(",")
                                nc_active_array = nc_active.split(",")
                                for nc_act in nc_active_array:
                                    for up_nc_act in updated_nc_active:
                                        nc_act_k, _ = nc_act.split(":")
                                        up_nc_act_k, _ = up_nc_act.split(":")
                                        if nc_act_k in up_nc_act_k:
                                            updated_nc_active.remove(up_nc_act)
                                nc_active_array.extend(updated_nc_active)
                                nc_active = ",".join(set(nc_active_array))
                            mapping.update({"nc_active": nc_active})
                        if item.status.allocated_shards not in (0,):
                            mapping.update(
                                {"allocated_shards": item.status.allocated_shards}
                            )

                    if list_merge_strategy in ("replace",):
                        if item.spec.WhichOneof("nc_spec") not in ("", None):
                            nc_spec = get_endpoint_spec(item)

                            nc_spec_type = item.spec.WhichOneof("nc_spec")
                            mapping.update(
                                {
                                    "nc_spec_type": nc_spec_type,
                                }
                            )
                            if nc_spec_type in (
                                "MsMptpSpec",
                                "MsPtpSpec",
                                "ms_ptp",
                                "ms_mptp",
                            ):
                                if MessageToJson(
                                    nc_spec.sgup_endpoint,
                                    including_default_value_fields=True,
                                ) not in (
                                    "",
                                    None,
                                ):
                                    mapping.update(
                                        {
                                            "sgup_endpoints": MessageToJson(
                                                nc_spec.sgup_endpoint,
                                                including_default_value_fields=True,
                                            )
                                        }
                                    )

                            else:
                                if f"{nc_spec.sgup_endpoint}" not in (
                                    "",
                                    None,
                                ):
                                    mapping.update(
                                        {
                                            "sgup_endpoints": ",,".join(
                                                [
                                                    MessageToJson(
                                                        ep,
                                                        including_default_value_fields=True,
                                                    )
                                                    for ep in nc_spec.sgup_endpoint
                                                ]
                                            )
                                        }
                                    )

                            if nc_spec_type in (
                                "SsPtpSpec",
                                "MsPtpSpec",
                                "ss_ptp",
                                "ms_ptp",
                            ):
                                if MessageToJson(
                                    nc_spec.tsf_endpoint,
                                    including_default_value_fields=True,
                                ) not in (
                                    "",
                                    None,
                                ):
                                    mapping.update(
                                        {
                                            "tsf_endpoints": MessageToJson(
                                                nc_spec.tsf_endpoint,
                                                including_default_value_fields=True,
                                            )
                                        }
                                    )

                            else:
                                if f"{nc_spec.tsf_endpoint}" not in (
                                    "",
                                    None,
                                ):
                                    mapping.update(
                                        {
                                            "tsf_endpoints": ",,".join(
                                                [
                                                    MessageToJson(
                                                        ep,
                                                        including_default_value_fields=True,
                                                    )
                                                    for ep in nc_spec.tsf_endpoint
                                                ]
                                            )
                                        }
                                    )

                        if item.status.nc_active not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "nc_active": ",".join(
                                        {
                                            f"{key}:{value}"
                                            for key, value in item.status.nc_active.items()
                                        }
                                    ),
                                }
                            )

                        if item.status.allocated_shards not in (0,):
                            mapping.update(
                                {"allocated_shards": item.status.allocated_shards}
                            )

                    # redis key for item
                    _redis_key_ingress = f"/ingress/nc/{item_name}"

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "updating item in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key_ingress, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send update notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "update", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                if item_type == "traffic_steering_function":
                    if list_merge_strategy in (
                        "union",
                        "replace",
                    ):
                        if item.spec.default_endpoint.endpoint_name not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "default_endpoint": MessageToJson(
                                        item.spec.default_endpoint,
                                        including_default_value_fields=True,
                                    ),
                                }
                            )

                    # redis key for item
                    _redis_key_ingress = f"/ingress/tsf/{item_name}"

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "updating item in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key_ingress, mapping=mapping)

                    # store Name in {item_type}Set (i.e. ServiceGatewaySet)
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "update", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                if item_type == "service_gateway":
                    # redis key for item
                    _redis_key_ingress = f"/ingress/sg/{item_name}"

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "updating item in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key_ingress, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "update", "type": item_type, "name": item_name}
                        ),
                    )
                    return fill_item(item_type, mapping)

                if item_type == "service_gateway_user_plane":
                    if list_merge_strategy in (
                        "union",
                        "replace",
                    ):
                        if item.service_gateway_name not in ("",):
                            mapping.update(
                                {
                                    "service_gateway_name": item.service_gateway_name,
                                }
                            )
                        if item.spec.max_session_count not in (0,):
                            mapping.update(
                                {
                                    "max_session_count": int(
                                        item.spec.max_session_count
                                    ),
                                }
                            )
                        if item.spec.max_shards not in (0,):
                            mapping.update(
                                {
                                    "max_shards": int(item.spec.max_shards),
                                }
                            )
                        if Maintenance.MaintenanceReq.Name(
                            item.maintenance.maintenance_req
                        ) not in ("",):
                            mapping.update(
                                {
                                    "maintenance": Maintenance.MaintenanceReq.Name(
                                        item.maintenance.maintenance_req
                                    ),
                                }
                            )
                        if item.spec.default_endpoint.endpoint_name not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "default_endpoint": MessageToJson(
                                        item.spec.default_endpoint,
                                        including_default_value_fields=True,
                                    ),
                                }
                            )
                        if item.status.allocated_session_count not in (0,):
                            mapping.update(
                                {
                                    "allocated_session_count": int(
                                        item.status.allocated_session_count
                                    ),
                                }
                            )
                        if item.status.allocated_shards not in (0,):
                            mapping.update(
                                {
                                    "allocated_shards": int(
                                        item.status.allocated_shards
                                    ),
                                }
                            )
                    if list_merge_strategy in ("union",):
                        if len(item.spec.supported_service_group) > 0:
                            _ssg = mapping.get("supported_service_group", "").split(",")
                            for svcgrp in item.spec.supported_service_group:
                                if svcgrp not in _ssg:
                                    _ssg.append(svcgrp)

                            mapping.update(
                                {
                                    "supported_service_group": ",".join(
                                        svcgrp for svcgrp in _ssg
                                    )
                                }
                            )
                    if list_merge_strategy in ("replace",):
                        if item.spec.supported_service_group not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "supported_service_group": ",".join(
                                        svcgrp
                                        for svcgrp in item.spec.supported_service_group
                                        if svcgrp not in ("",)
                                    )
                                }
                            )

                    # redis key for item
                    _redis_key_ingress = f"/ingress/up/{item_name}"

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "updating item in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key_ingress, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "update", "type": item_type, "name": item_name}
                        ),
                    )
                    return fill_item(item_type, mapping)

                if item_type == "session_context":
                    if list_merge_strategy in (
                        "union",
                        "replace",
                    ):
                        tsf = item.spec.traffic_steering_function
                        if tsf not in ("",):
                            mapping.update(
                                {
                                    "traffic_steering_function": tsf,
                                }
                            )

                        if item.spec.required_quality not in (0,):
                            mapping.update(
                                {
                                    "required_quality": item.spec.required_quality,
                                }
                            )
                        source_mac_address = item.spec.session_filter.source_mac_address
                        if source_mac_address not in ("",):
                            mapping.update(
                                {
                                    "source_mac_address": source_mac_address,
                                }
                            )
                        if item.spec.session_filter.svlan not in (0,):
                            mapping.update(
                                {
                                    "s_tag": item.spec.session_filter.svlan,
                                }
                            )
                        if item.spec.session_filter.cvlan not in (0,):
                            mapping.update(
                                {
                                    "c_tag": item.spec.session_filter.cvlan,
                                }
                            )
                        if item.spec.circuit_id not in ("",):
                            mapping.update(
                                {
                                    "circuit_id": item.spec.circuit_id,
                                }
                            )
                        if item.spec.remote_id not in ("",):
                            mapping.update(
                                {
                                    "remote_id": item.spec.remote_id,
                                }
                            )
                        if item.spec.desired_state.shard not in ("",):
                            mapping.update(
                                {
                                    "desired_shard": item.spec.desired_state.shard,
                                }
                            )
                        if item.status.current_state.user_plane_shard not in ("",):
                            mapping.update(
                                {
                                    "user_plane_shard": item.status.current_state.user_plane_shard,
                                }
                            )
                        if item.status.current_state.tsf_shard not in ("",):
                            mapping.update(
                                {
                                    "tsf_shard": item.status.current_state.tsf_shard,
                                }
                            )
                    if list_merge_strategy in ("union",):
                        if f"{item.spec.required_service_group}" not in (
                            "",
                            "[]",
                            [],
                            None,
                        ):
                            new_rsg = ",".join(
                                [
                                    item
                                    for item in item.spec.required_service_group
                                    if item not in ("",)
                                ]
                            ).split(",")

                            if mapping.get("required_service_group") not in (
                                "",
                                "[]",
                                [],
                                None,
                            ):
                                old_rsg = mapping.get("required_service_group").split(
                                    ","
                                )
                                for n_rsg in new_rsg:
                                    if n_rsg in old_rsg:
                                        old_rsg.remove(n_rsg)
                                new_rsg.extend(old_rsg)
                            mapping.update(
                                {
                                    "required_service_group": ",".join(
                                        [rsg for rsg in new_rsg if rsg not in ("",)]
                                    ),
                                }
                            )
                    if list_merge_strategy in ("replace",):
                        if item.spec.required_service_group not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "required_service_group": ",".join(
                                        [
                                            item
                                            for item in item.spec.required_service_group
                                            if item not in ("",)
                                        ]
                                    )
                                }
                            )
                    # redis key for item
                    _redis_key_ingress = f"/ingress/ct/{item_name}"

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "updating item in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key_ingress, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "update", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                if item_type == "shard":
                    if list_merge_strategy in (
                        "union",
                        "replace",
                    ):
                        desired_sgup = (
                            item.spec.desired_state.service_gateway_user_plane
                        )
                        current_sgup = (
                            item.status.current_state.service_gateway_user_plane
                        )
                        if item.spec.max_session_count not in (0,):
                            mapping.update(
                                {
                                    "max_session_count": item.spec.max_session_count,
                                }
                            )
                        if item.spec.virtual_mac not in ("",):
                            mapping.update(
                                {
                                    "virtual_mac": item.spec.virtual_mac,
                                }
                            )
                        if item.spec.desired_state.service_gateway_user_plane not in (
                            "",
                        ):
                            mapping.update(
                                {
                                    "desired_service_gateway_user_plane": desired_sgup,
                                }
                            )

                        if item.status.allocated_session_count not in (0,):
                            mapping.update(
                                {
                                    "allocated_session_count": item.status.allocated_session_count,
                                }
                            )
                        if (
                            item.status.current_state.service_gateway_user_plane
                            not in ("",)
                        ):
                            mapping.update(
                                {
                                    "current_service_gateway_user_plane": current_sgup,
                                }
                            )

                        if item.mbb.mbb_state not in (0,):
                            mapping.update(
                                {
                                    "mbb_state": Shard.Mbb.MbbState.Name(
                                        item.mbb.mbb_state
                                    ),
                                }
                            )
                    if list_merge_strategy in ("union",):
                        if item.status.current_state.tsf_network_connection not in (
                            "",
                            "{}",
                            {},
                        ):
                            current_tsfs = (
                                item.status.current_state.tsf_network_connection.items()
                            )
                            new_current_tsf_network_connection = ",".join(
                                {f"{key}:{value}" for key, value in current_tsfs}
                            ).split(",")
                            if mapping.get("current_tsf_network_connection") not in (
                                "",
                            ):
                                old_current_tsf_network_connection = mapping.get(
                                    "current_tsf_network_connection", ""
                                ).split(",")
                                for o_ctsf_nc in old_current_tsf_network_connection:
                                    if o_ctsf_nc in new_current_tsf_network_connection:
                                        old_current_tsf_network_connection.remove(
                                            o_ctsf_nc
                                        )
                                new_current_tsf_network_connection.extend(
                                    old_current_tsf_network_connection
                                )
                            mapping.update(
                                {
                                    "current_tsf_network_connection": ",".join(
                                        {
                                            nc
                                            for nc in new_current_tsf_network_connection
                                            if nc not in ("",)
                                        }
                                    ),
                                }
                            )
                        if item.spec.desired_state.network_connection not in (
                            "",
                            [],
                            "[]",
                            None,
                        ):
                            new_desired_network_connection = ",".join(
                                nc
                                for nc in item.spec.desired_state.network_connection
                                if nc not in ("",)
                            ).split(",")
                            if mapping.get("desired_network_connection") not in (
                                "",
                                None,
                            ):
                                old_desired_network_connection = mapping.get(
                                    "desired_network_connection"
                                ).split(",")
                                for o_dnc in old_desired_network_connection:
                                    if o_dnc in new_desired_network_connection:
                                        old_desired_network_connection.remove(o_dnc)
                                new_desired_network_connection.extend(
                                    old_desired_network_connection
                                )
                            mapping.update(
                                {
                                    "desired_network_connection": ",".join(
                                        nc
                                        for nc in new_desired_network_connection
                                        if nc not in ("",)
                                    ),
                                }
                            )
                        if item.spec.prefix not in (
                            "",
                            "[]",
                            [],
                            None,
                        ):
                            new_prefix = ",".join(
                                prfx for prfx in item.spec.prefix
                            ).split(",")
                            if mapping.get("prefix") not in (
                                "",
                                "[]",
                                [],
                                None,
                            ):
                                old_prefix = mapping.get("prefix").split(",")
                                for o_prefix in old_prefix:
                                    if o_prefix in new_prefix:
                                        new_prefix.remove(o_prefix)
                                new_prefix.extend(old_prefix)
                            mapping.update(
                                {
                                    "prefix": ",".join(prfx for prfx in new_prefix),
                                }
                            )
                        if item.status.service_groups_supported not in (
                            "",
                            [],
                            "[]",
                            None,
                        ):
                            new_sgs = ",".join(
                                sg
                                for sg in item.status.service_groups_supported
                                if sg not in ("",)
                            ).split(",")
                            if mapping.get("service_groups_supported") not in (
                                "",
                                "[]",
                                [],
                                None,
                            ):
                                old_sgs = mapping.get("service_groups_supported").split(
                                    ","
                                )
                                for _service_gateway in old_sgs:
                                    if _service_gateway in new_sgs:
                                        new_sgs.remove(_service_gateway)
                                new_sgs.extend(old_sgs)
                            mapping.update(
                                {
                                    "service_groups_supported": ",".join(
                                        sgs for sgs in new_sgs if sgs not in ("",)
                                    ),
                                }
                            )
                    if list_merge_strategy in ("replace",):
                        if item.status.current_state.tsf_network_connection not in (
                            "",
                            None,
                        ):
                            tsf_nc_items = (
                                item.status.current_state.tsf_network_connection.items()
                            )
                            mapping.update(
                                {
                                    "current_tsf_network_connection": ",".join(
                                        {
                                            f"{key}:{value}"
                                            for key, value in tsf_nc_items
                                        }
                                    ),
                                }
                            )
                        if item.spec.desired_state.network_connection not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "desired_network_connection": ",".join(
                                        nc
                                        for nc in item.spec.desired_state.network_connection
                                        if nc not in ("",)
                                    ),
                                }
                            )
                        if item.spec.prefix not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "prefix": ",".join(
                                        prfx
                                        for prfx in item.spec.prefix
                                        if prfx not in ("",)
                                    ),
                                }
                            )
                        if item.status.service_groups_supported not in (
                            "",
                            None,
                        ):
                            mapping.update(
                                {
                                    "service_groups_supported": ",".join(
                                        sgs
                                        for sgs in item.status.service_groups_supported
                                        if sgs not in ("",)
                                    ),
                                }
                            )
                    # redis key for item
                    _redis_key_ingress = f"/ingress/sh/{item_name}"

                    self.log.debug(
                        {
                            "entity": str(self),
                            "event": "updating item in redis cache",
                            "redis_key": _redis_key_ingress,
                            "mapping": mapping,
                        }
                    )

                    # store Item in redis backend
                    rconn.hset(_redis_key_ingress, mapping=mapping)

                    # store Name in {item_type}Set
                    rconn.sadd(f"{snake_case2studly_case(item_type)}Set", item_name)

                    # send create notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {"cmd": "update", "type": item_type, "name": item_name}
                        ),
                    )

                    return fill_item(item_type, mapping)

                # Return Error when Item Type is Unknown
                self.log.error(
                    {
                        "entity": str(self),
                        "function": "UpdateV1",
                        "event": f"Wrong Item Type: {item_type}",
                        "traceback": traceback.format_exc(),
                    }
                )
                return Item()

        except redis.exceptions.ConnectionError as error:
            self.log.error(
                {
                    "entity": str(self),
                    "event": "redis connection failed",
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
            )
            return Item()

    def ReadV1(self, request, context):
        """read"""
        try:
            with self.redis_open() as rconn:
                # get itemtypes
                if request.itemtype is None:
                    _item_type = [
                        "service_gateway",
                        "service_gateway_user_plane",
                        "traffic_steering_function",
                        "network_connection",
                        "shard",
                        "session_context",
                    ]
                else:
                    _item_type = request.itemtype

                if request.itemstate is None:
                    _item_state = []
                else:
                    _item_state = request.itemstate

                if request.parent is None:
                    _parent = []
                else:
                    _parent = []
                    for parent in request.parent:
                        _parent.append(parent.value)

                if request.name is None:
                    _names = []
                else:
                    _names = []
                    for name in request.name:
                        _names.append(name.value)

                # if request is not a watch request only list items
                if not request.watch:
                    for _type in _item_type:
                        for item in rconn.smembers(
                            f"{snake_case2studly_case(ItemType.Name(_type))}Set"
                        ):
                            # redis key for item
                            if _type in (ItemType.service_gateway,):
                                _redis_key_ingress = f"/ingress/sg/{item}"
                                _redis_key_egress = f"/egress/sg/{item}"
                            elif _type in (ItemType.service_gateway_user_plane,):
                                _redis_key_ingress = f"/ingress/up/{item}"
                                _redis_key_egress = f"/egress/up/{item}"
                            elif _type in (ItemType.traffic_steering_function,):
                                _redis_key_ingress = f"/ingress/tsf/{item}"
                                _redis_key_egress = f"/egress/tsf/{item}"
                            elif _type in (ItemType.network_connection,):
                                _redis_key_ingress = f"/ingress/nc/{item}"
                                _redis_key_egress = f"/egress/nc/{item}"
                            elif _type in (ItemType.session_context,):
                                _redis_key_ingress = f"/ingress/ct/{item}"
                                _redis_key_egress = f"/egress/ct/{item}"
                            elif _type in (ItemType.shard,):
                                _redis_key_ingress = f"/ingress/sh/{item}"
                                _redis_key_egress = f"/egress/sh/{item}"
                            else:
                                continue

                            # out of sync?
                            if not rconn.exists(
                                _redis_key_ingress
                            ) and not rconn.exists(_redis_key_egress):
                                continue

                            # get item from redis backend
                            if rconn.exists(_redis_key_egress):
                                mapping = rconn.hgetall(_redis_key_egress)
                                # self.log.debug(
                                #     {
                                #         "entity": str(self),
                                #         "event": "reading item from redis cache",
                                #         "redis_key": _redis_key_egress,
                                #         "mapping": mapping,
                                #     }
                                # )
                            elif rconn.exists(_redis_key_ingress):
                                mapping = rconn.hgetall(_redis_key_ingress)
                                # self.log.debug(
                                #     {
                                #         "entity": str(self),
                                #         "event": "reading item from redis cache",
                                #         "redis_key": _redis_key_ingress,
                                #         "mapping": mapping,
                                #     }
                                # )
                            # only process items with derived state when itemstate is provided
                            if (
                                len(_item_state) > 0
                                and mapping.get("derive_state") not in _item_state
                            ):
                                continue

                            # only process items with name when name is provided
                            if len(_names) > 0 and item not in _names:
                                continue

                            # Figure out Parent logic
                            if len(_parent) > 0:
                                continue

                            # append filled out item by type to sssitem array
                            yield fill_item(ItemType.Name(_type), mapping)

                # if request is a watch request create stream and keep open
                else:
                    rconn_p = rconn.pubsub()
                    rconn_p.subscribe(
                        [
                            "UpdatesEgress",
                        ]
                    )

                    for msg in rconn_p.listen():
                        # ignore non message frames
                        if msg.get("type", None) not in ("message",) or msg.get(
                            "channel", None
                        ) not in ("UpdatesEgress",):
                            continue

                        # extract message data
                        data = json.loads(msg.get("data", {}))

                        # ignore message without data
                        if data in ({},):
                            continue

                        # extract update type
                        _type = data.get("type", None)

                        # extract update name
                        _name = data.get("name", None)

                        # extract update item_status
                        # include derived_state in msg
                        # _item_status = data.get("derived_state", None)

                        # only process items with derived state when itemstate is provided
                        # if _item_status not in _item_state:
                        #     continue

                        # only process items with name when name is provided
                        if len(_names) > 0 and _name not in _names:
                            self.log.debug(
                                {
                                    "entity": str(self),
                                    "event": "name not in name list",
                                    "name list": _names,
                                    "name": _name,
                                }
                            )
                            continue

                        # redis key for item
                        if _type in ("service_gateway",):
                            _redis_key = f"/egress/sg/{_name}"
                        elif _type in ("service_gateway_user_plane",):
                            _redis_key = f"/egress/up/{_name}"
                        elif _type in ("traffic_steering_function",):
                            _redis_key = f"/egress/tsf/{_name}"
                        elif _type in ("network_connection",):
                            _redis_key = f"/egress/nc/{_name}"
                        elif _type in ("session_context",):
                            _redis_key = f"/egress/ct/{_name}"
                        elif _type in ("shard",):
                            _redis_key = f"/egress/sh/{_name}"
                        else:
                            continue

                        # Figure out Parent logic
                        # if _parent is not []:
                        #     continue

                        # does item exist?
                        if not rconn.exists(_redis_key):
                            # mapping = {"name": _name, "derived_state": _item_status}
                            # update item_status, defaults to unknown
                            # mapping.update(
                            #    {
                            #        "derived_state":
                            #           DerivedState.Value(mapping.get("derived_state", "unknown")),
                            #    }
                            # )
                            mapping = {"name": _name, "derived_state": "deleted"}
                            yield fill_item(_type, mapping)
                        else:
                            mapping = rconn.hgetall(_redis_key)
                            # self.log.debug(
                            #     {
                            #         "entity": str(self),
                            #         "event": "reading item from redis cache for notification",
                            #         "redis_key": _redis_key,
                            #         "mapping": mapping,
                            #     }
                            # )
                            # send response
                            yield fill_item(_type, mapping)

        except redis.exceptions.ConnectionError as error:
            self.log.error(
                {
                    "entity": str(self),
                    "event": "redis connection failed",
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
            )

        except GeneratorExit:
            self.log.warning(
                {
                    "entity": str(self),
                    "event": "sss read stream ended",
                }
            )

    def DeleteV1(self, request, context):
        """delete item"""
        self.log.debug(
            {
                "event": inspect.currentframe().f_code.co_name,
                "request": str(request),
            }
        )

        try:
            with self.redis_open() as rconn:
                # get item name
                if request.value in ("",):
                    self.log.error(
                        {
                            "entity": str(self),
                            "function": "DeleteV1",
                            "event": "Item name not Provided",
                        }
                    )
                item_name = request.value

                item_types = [
                    "service_gateway",
                    "service_gateway_user_plane",
                    "traffic_steering_function",
                    "network_connection",
                    "shard",
                    "session_context",
                ]
                for item_type in item_types:
                    _type = f"{snake_case2studly_case(item_type)}Set"
                    # check if item is in <Item>Sets
                    if not rconn.sismember(_type, item_name):
                        continue
                    # delete Item from ItemSet in redis backend
                    rconn.srem(_type, item_name)

                    # redis key for item
                    if item_type in ("service_gateway",):
                        _redis_key = f"/egress/sg/{item_name}"
                    elif item_type in ("service_gateway_user_plane",):
                        _redis_key = f"/egress/up/{item_name}"
                    elif item_type in ("traffic_steering_function",):
                        _redis_key = f"/egress/tsf/{item_name}"
                    elif item_type in ("network_connection",):
                        _redis_key = f"/egress/nc/{item_name}"
                    elif item_type in ("session_context",):
                        _redis_key = f"/egress/ct/{item_name}"
                    elif item_type in ("shard",):
                        _redis_key = f"/egress/sh/{item_name}"
                    else:
                        _redis_key = None

                    # delete egress item in redis backend
                    if rconn.exists(_redis_key):
                        rconn.delete(_redis_key)

                    # redis key for item
                    if item_type in ("service_gateway",):
                        _redis_key = f"/ingress/sg/{item_name}"
                    elif item_type in ("service_gateway_user_plane",):
                        _redis_key = f"/ingress/up/{item_name}"
                    elif item_type in ("traffic_steering_function",):
                        _redis_key = f"/ingress/tsf/{item_name}"
                    elif item_type in ("network_connection",):
                        _redis_key = f"/ingress/nc/{item_name}"
                    elif item_type in ("session_context",):
                        _redis_key = f"/ingress/ct/{item_name}"
                    elif item_type in ("shard",):
                        _redis_key = f"/ingress/sh/{item_name}"
                    else:
                        _redis_key = None

                    # delete ingress item in redis backend
                    if rconn.exists(_redis_key):
                        rconn.delete(_redis_key)

                    # send update notification
                    rconn.rpush(
                        "UpdatesIngress",
                        json.dumps(
                            {
                                "type": item_type,
                                "cmd": "delete",
                                "name": item_name,
                            }
                        ),
                    )

                    return StringValue(value=f"{item_name} deleted!")
                return StringValue(value=f"{item_name } doesn't Exist")

        except redis.exceptions.ConnectionError as error:
            self.log.error(
                {
                    "entity": str(self),
                    "event": "redis connection failed",
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
            )
            return StringValue()

    def LookupV1(self, request, context):
        """lookup"""
        self.log.debug(
            {
                "event": inspect.currentframe().f_code.co_name,
                "request": str(request),
            }
        )

        try:
            with self.redis_open() as rconn:
                ctx_name = session_hash(request)

                # redis key for item
                _redis_key = f"/egress/ct/{ctx_name}"
                if rconn.exists(_redis_key):
                    mapping = rconn.hgetall(_redis_key)
                    return fill_item("SessionContext", mapping).session_context

                _timestamp = Timestamp()
                _timestamp.FromDatetime(datetime.datetime.utcnow())

                # item parameters
                mapping = {
                    "name": ctx_name,
                    "description": "",
                    "derived_state": "updating",
                    "created": _timestamp.ToDatetime().timestamp(),
                    "last_updated": _timestamp.ToDatetime().timestamp(),
                    "desired_shard": request.desired_state.shard,
                    "required_quality": request.required_quality,
                    "required_service_group": ",".join(
                        [
                            rsg
                            for rsg in request.required_service_group
                            if rsg not in ("",)
                        ]
                    ),
                    "source_mac_address": request.session_filter.source_mac_address,
                    "s_tag": request.session_filter.svlan,
                    "c_tag": request.session_filter.cvlan,
                    "circuit_id": request.circuit_id,
                    "remote_id": request.remote_id,
                }

                # This is the lookup logic we intent to use, but won't work currently.
                # Keeping it for now as comment

                # if mapping.get("circuit_id") in ("",):
                #     mapping["circuit_id"] = mapping.get("source_mac_address", "")

                # # session lookup
                # ctx_names = []

                # # 1. circuit-id + smac + stag + ctag
                # ctx_names.append(session_hash(request))

                # # 2. circuit-id + smac + stag
                # request.session_filter.cvlan = 0
                # ctx_names.append(session_hash(request))

                # # 3. circuit-id + stag
                # request.session_filter.source_mac_address = ""
                # ctx_names.append(session_hash(request))

                # # 4. circuit-id + smac
                # request.session_filter.svlan = 0
                # request.session_filter.source_mac_address = mapping.get(
                #     "source_mac_address"
                # )
                # ctx_names.append(session_hash(request))

                # # 5. circuit-id
                # request.session_filter.svlan = 0
                # request.session_filter.source_mac_address = ""
                # ctx_names.append(session_hash(request))

                # self.log.debug(
                #     {
                #         "entity": str(self),
                #         "event": "sctx lookup based on different hash combinations",
                #         "sctx.names": ctx_names,
                #     }
                # )

                # for ctx_name in ctx_names:
                #     # redis key for item
                #     _redis_key = f"/egress/ct/{ctx_name}"

                #     if not rconn.exists(_redis_key):
                #         continue

                #     self.log.debug(
                #         {
                #             "entity": str(self),
                #             "event": "sctx lookup successful (different hashes)",
                #             "sctx.name": ctx_name,
                #         }
                #     )

                #     mapping = rconn.hgetall(_redis_key)
                #     return fill_item("SessionContext", mapping).session_context

                # if desired_shard is blank, set to default shard
                if mapping.get("desired_shard") in (
                    "",
                    None,
                ):
                    mapping["desired_shard"] = self.default_shard_name

                # redis key for item
                _redis_key = f"/ingress/ct/{ctx_name}"

                # store Item in redis backend
                rconn.hset(_redis_key, mapping=mapping)

                # store Name in SessionContextSet
                rconn.sadd(
                    "SessionContextSet",
                    ctx_name,
                )

                self.log.info(
                    {
                        "entity": str(self),
                        "event": "create new session context due to failed lookup",
                        "name": ctx_name,
                        "mapping": mapping,
                    }
                )

                # send create notification
                rconn.rpush(
                    "UpdatesIngress",
                    json.dumps(
                        {
                            "cmd": "create",
                            "type": "session_context",
                            "name": ctx_name,
                        }
                    ),
                )

                return fill_item("SessionContext", mapping).session_context

        except redis.exceptions.ConnectionError as error:
            self.log.error(
                {
                    "entity": str(self),
                    "event": "redis connection failed",
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
            )
            return SessionContext()


def main():
    """main function"""
    server = grpc.server(
        futures.ThreadPoolExecutor(
            max_workers=1,
        )
    )
    service_v1_pb2_grpc.add_upsfServicer_to_server(
        SssUpsfServicer(max_workers=1),
        server,
    )
    server.add_insecure_port("[::]:50051")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    logging.basicConfig()
    main()

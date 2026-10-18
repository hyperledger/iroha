"""Bounded lifetime for one canonical Requests dispatch in an owned process.

Requests keeps ownership of preparation, proxies, TLS and HTTP framing inside
one owned worker, including potentially blocking NETRC and system proxy reads.
The parent snapshots supported in-memory configuration and owns the absolute
deadline and private bounded Norito pipes. Explicit request credentials never
enter command arguments, files or diagnostics; the worker receives the captured
ambient environment for the original Requests environment/auth resolution.
Only standard Sessions/adapters are supported. There is no transport fallback.
"""
from __future__ import annotations

import functools
import io
import logging
import math
import os
import selectors
import subprocess
import sys
import threading
import time
import types
from collections import OrderedDict

import requests
from norito import (
    SchemaDescriptor,
    StructAdapter,
    StructField,
    bool_,
    bytes_,
    decode,
    encode,
    seq,
    string,
    tuple_adapter,
    u8,
    u16,
    u64,
)
from norito.header import COMPACT_LEN, NoritoHeader

_FRAME_LIMIT = 512 * 1024
_BODY_LIMIT = 256 * 1024
_HEADERS_LIMIT = 64 * 1024
_PAIRS_LIMIT = 128
_METHOD_LIMIT = 16
_MEDIA_LIMIT = 256
_PAIRS = seq(tuple_adapter(string(), string()))
_LOG_SINKS = seq(tuple_adapter(u64(), u64(), string(), string(), string(), string()))
_ALIAS_EVALUATIONS = seq(tuple_adapter(string(), string(), bool_(), u64(), u64(), u64(), seq(u64()), bool_()))
_POLICY_FIELDS = ("positive_ttl_secs", "refresh_window_secs", "hard_expiry_secs",
                  "negative_ttl_secs", "revocation_ttl_secs", "rotation_max_age_secs",
                  "successor_grace_secs", "governance_grace_secs")
_EVALUATION_FIELDS = ("state", "status_label", "rotation_due", "age_seconds",
                      "generated_at_unix", "expires_at_unix", "expires_in_seconds", "servable")
_REQUEST = StructAdapter([
    StructField("method", string()), StructField("url", string()),
    StructField("headers", _PAIRS), StructField("body", bytes_()),
    StructField("session_headers", _PAIRS), StructField("session_params", _PAIRS),
    StructField("trust_env", bool_()),
    StructField("proxies", _PAIRS), StructField("verify", u8()),
    StructField("ca_path", string()), StructField("cert", seq(string())),
    StructField("timeout_ns", u64()), StructField("deadline_ns", u64()),
    StructField("max_body", u64()), StructField("media_type", string()),
    StructField("alias_policy", seq(u64())), StructField("log_name", string()),
    StructField("log_enabled", bool_()), StructField("log_sinks", _LOG_SINKS),
])
_RESPONSE = StructAdapter([
    StructField("error", u8()), StructField("status", u16()),
    StructField("headers", _PAIRS), StructField("body", bytes_()),
    StructField("request_method", string()), StructField("request_url", string()),
    StructField("request_headers", _PAIRS), StructField("request_body", bytes_()),
    StructField("alias_evaluation", _ALIAS_EVALUATIONS), StructField("error_message", string()),
])
_REQUEST_SCHEMA = SchemaDescriptor.type_name("iroha_python::RequestsDeadlineRequestV1")
_RESPONSE_SCHEMA = SchemaDescriptor.type_name("iroha_python::RequestsDeadlineResponseV1")


def _text_size(value, label, maximum=_HEADERS_LIMIT):
    if type(value) is not str:
        raise TypeError(f"bounded Requests {label} requires an exact string")
    # Reject by character count before UTF-8 encoding or any scalar-sized copy.
    if len(value) > maximum:
        raise ValueError(f"bounded Requests {label} exceeds its byte limit")
    size = 0
    for character in value:
        point = ord(character)
        if 0xD800 <= point <= 0xDFFF:
            raise ValueError(f"bounded Requests {label} is not UTF-8 text")
        size += 1 if point < 0x80 else 2 if point < 0x800 else 3 if point < 0x10000 else 4
        if size > maximum:
            raise ValueError(f"bounded Requests {label} exceeds its byte limit")
    return size


def _mapping(value, label, maximum=_PAIRS_LIMIT, *, ordered=True):
    kind = type(value)
    if kind is not dict and not (ordered and kind is OrderedDict):
        raise TypeError(f"bounded Requests {label} requires closed builtin mapping storage")
    if kind is OrderedDict:
        attributes = object.__getattribute__(value, "__dict__")
        if type(attributes) is not dict or dict.__len__(attributes) != 0:
            raise TypeError(f"bounded Requests {label} rejects modified mapping methods")
    if len(value) > maximum:
        raise ValueError(f"bounded Requests {label} exceeds its entry limit")
    # Bind the builtin descriptor, never caller-provided .items/get/len methods.
    return dict.items(value) if kind is dict else OrderedDict.items(value)


def _object_state(value, label, maximum=64):
    state = object.__getattribute__(value, "__dict__")
    for key, _ in _mapping(state, label, maximum, ordered=False):
        _text_size(key, label, 256)
    return state


def _pairs(value, label):
    result = []
    size = 0
    if type(value) is requests.structures.CaseInsensitiveDict:
        state = _object_state(value, label, 1)
        if tuple(state) != ("_store",):
            raise TypeError(f"bounded Requests {label} rejects modified header storage")
        stored = state["_store"]
        if type(stored) is not OrderedDict:
            raise TypeError(f"bounded Requests {label} requires ordered builtin header storage")
        rows = _mapping(stored, label)
        for folded, pair in rows:
            _text_size(folded, label)
            if type(pair) is not tuple or len(pair) != 2:
                raise TypeError(f"bounded Requests {label} rejects custom header entries")
            key, item = pair
            size += _text_size(key, label) + _text_size(item, label)
            if size > _HEADERS_LIMIT:
                raise ValueError(f"bounded Requests {label} exceeds its byte limit")
            if folded != key.lower():
                raise ValueError(f"bounded Requests {label} has noncanonical folded keys")
            result.append((key, item))
    else:
        for key, item in _mapping(value, label):
            size += _text_size(key, label) + _text_size(item, label)
            if size > _HEADERS_LIMIT:
                raise ValueError(f"bounded Requests {label} exceeds its byte limit")
            result.append((key, item))
    return result


def _same_default(actual, expected, object_types, lock_type, depth=0):
    # Type identity must precede every operation on caller-owned nested values.
    kind = type(expected)
    if type(actual) is not kind or depth > 16:
        raise TypeError("absolute-deadline requests reject custom nested Session storage")
    if kind is str:
        _text_size(actual, "Session configuration")
        equal = actual == expected
    elif kind in (type(None), bool, int, float):
        if kind is int and actual.bit_length() > 64:
            raise ValueError("absolute-deadline Session integer exceeds its bound")
        equal = actual == expected
    elif kind in (dict, OrderedDict):
        rows = _mapping(actual, "Session configuration")
        if len(actual) != len(expected):
            raise ValueError("absolute-deadline requests reject altered Session configuration")
        for key, item in rows:
            _text_size(key, "Session configuration key", 256)
            if key not in expected:
                raise ValueError("absolute-deadline requests reject altered Session configuration")
            _same_default(item, expected[key], object_types, lock_type, depth + 1)
        return
    elif kind in (tuple, list, set, frozenset):
        if len(actual) > _PAIRS_LIMIT or len(actual) != len(expected):
            raise ValueError("absolute-deadline requests reject altered Session collection")
        if kind in (set, frozenset):
            for item in actual:
                _text_size(item, "Session configuration item", 256)
            equal = actual == expected
        else:
            for item, reference in zip(actual, expected, strict=True):
                _same_default(item, reference, object_types, lock_type, depth + 1)
            return
    elif kind is functools.partial:
        if _object_state(actual, "Session partial", 0):
            raise TypeError("absolute-deadline requests reject custom partial attributes")
        _same_default(actual.func, expected.func, object_types, lock_type, depth + 1)
        _same_default(actual.args, expected.args, object_types, lock_type, depth + 1)
        _same_default(actual.keywords, expected.keywords, object_types, lock_type, depth + 1)
        return
    elif kind is lock_type:
        # No caller lock is acquired; only exact built-in lock storage is admissible.
        return
    elif kind in object_types:
        actual_state = _object_state(actual, "Session object")
        expected_state = _object_state(expected, "reference Session object")
        if kind is requests.adapters.PoolManager:
            expected_state = dict(expected_state)
            pools = requests.packages.urllib3.connectionpool
            expected_state["pool_classes_by_scheme"] = {
                "http": pools.HTTPConnectionPool, "https": pools.HTTPSConnectionPool,
            }
            # urllib3 shares these partial objects across fresh PoolManagers.
            # Construct immutable-default references so caller mutations to a
            # partial's keyword dictionary cannot modify our reference too.
            manager = requests.packages.urllib3.poolmanager
            expected_state["key_fn_by_scheme"] = {
                scheme: functools.partial(manager._default_key_normalizer, manager.PoolKey)
                for scheme in ("http", "https")
            }
        _same_default(actual_state, expected_state, object_types, lock_type, depth + 1)
        return
    elif kind in (type, types.FunctionType, types.BuiltinFunctionType):
        equal = actual is expected
    else:
        raise TypeError("absolute-deadline requests reject unsupported Session internals")
    if not equal:
        raise ValueError("absolute-deadline requests reject altered Session configuration")


def _standard_session(session):
    if type(session) is not requests.Session:
        raise TypeError("absolute-deadline requests require a standard Requests Session")
    state = _object_state(session, "Session", 32)
    # Construct only a fresh local reference; no caller Session method is invoked.
    with requests.Session() as reference:
        reference_state = _object_state(reference, "reference Session", 32)
        if len(state) != len(reference_state) or any(key not in reference_state for key in state):
            raise TypeError("absolute-deadline requests reject modified Session methods")
        reference_adapter = reference.adapters["http://"]
        object_types = {
            type(reference.cookies), type(reference.cookies._policy),
            type(reference_adapter), type(reference_adapter.max_retries),
            type(reference_adapter.poolmanager), type(reference_adapter.poolmanager.pools),
        }
        lock_type = type(reference.cookies._cookies_lock)
        supported = {"headers", "params", "proxies", "verify", "cert", "trust_env"}
        for key, expected in reference_state.items():
            if key not in supported:
                _same_default(state[key], expected, object_types, lock_type)
    return state


def _closed_fields(value, expected_type, fields, label):
    if type(value) is not expected_type:
        raise TypeError(f"bounded Requests rejects custom {label}")
    state = _object_state(value, label, len(fields))
    if len(state) != len(fields) or any(key not in fields for key in state):
        raise TypeError(f"bounded Requests rejects modified {label}")
    return state


def _unsigned(value, label, maximum=(1 << 64) - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"bounded Requests {label} must be an exact bounded integer")
    return value


def check_alias_state(metrics, previous):
    """Admit only finite builtin counters and the exact previous native evaluation."""
    from iroha_python.sorafs import SorafsAliasEvaluation
    for key, value in _mapping(metrics, "alias counters", 32, ordered=False):
        _text_size(key, "alias counter", 64)
        _unsigned(value, "alias counter", (1 << 64) - 2)
    if previous is not None:
        state = _closed_fields(previous, SorafsAliasEvaluation, _EVALUATION_FIELDS, "alias evaluation")
        _evaluation_size([tuple(state[key] if key != "expires_in_seconds" else
                                ([] if state[key] is None else [state[key]])
                                for key in _EVALUATION_FIELDS)])


def check_bounded_client(client):
    """Reject parent callbacks before any bounded-route client field is consumed."""
    from iroha_python.client import LocalSigningContext, ToriiClient
    from iroha_python.crypto import NetworkId
    if type(client) is not ToriiClient:
        raise TypeError("bounded staking preparation requires the canonical ToriiClient")
    state = dict(_object_state(client, "ToriiClient", 128))
    for method in ("prepare_public_lane_plan", "_request", "_require_local_signing_context"):
        if method in state:
            raise TypeError("bounded staking preparation rejects instance method overrides")
    timeout = state["_timeout"]
    if (type(timeout) not in (int, float)
            or type(timeout) is int and timeout.bit_length() > 64
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("bounded staking preparation timeout must be positive and finite")
    base_url = state["_base_url"]
    _text_size(base_url, "ToriiClient base URL")
    headers = state["_default_headers"]
    if type(headers) is not dict:
        raise TypeError("bounded staking preparation requires builtin default-header storage")
    headers = dict(_pairs(headers, "ToriiClient default headers"))
    network = None
    context = state["_ToriiClient__local_signing_context"]
    if context is not None:
        values = _closed_fields(context, LocalSigningContext, ("network_id",), "local signing context")
        network = values["network_id"]
        if type(network) is not NetworkId:
            raise TypeError("bounded staking preparation requires the native NetworkId")
    _standard_session(state["_session"])
    check_alias_state(state["_sorafs_alias_metrics"], state["_last_sorafs_alias_evaluation"])
    _alias_snapshot(state["_sorafs_alias_policy"], state["_sorafs_alias_warning_hook"],
                    state["_sorafs_alias_logger"])
    return {"timeout": timeout, "base_url": base_url, "headers": headers, "network": network}


def check_bounded_request(method, path, headers, data, json_body, params, timeout,
                          flags, deadline_ns, max_body, media_type):
    """Admit bounded-route scalars/storage before ordinary header/path helpers."""
    if any(type(flag) is not bool for flag in flags):
        raise TypeError("bounded Requests requires exact dispatch flags")
    _remaining(deadline_ns)
    _unsigned(max_body, "response body bound", _BODY_LIMIT)
    _text_size(media_type, "media type", _MEDIA_LIMIT)
    _text_size(method, "method", _METHOD_LIMIT)
    _text_size(path, "request path")
    copied_headers = None if headers is None else dict(_pairs(headers, "request headers"))
    if type(data) is not bytes or len(data) > 64 * 1024:
        raise ValueError("bounded Requests requires at most 64 KiB of immutable request bytes")
    if json_body is not None or params is not None:
        raise ValueError("bounded observation requires immutable bytes without parameters")
    if timeout is not None and (type(timeout) not in (int, float)
            or type(timeout) is int and timeout.bit_length() > 64
            or not math.isfinite(timeout) or timeout <= 0):
        raise ValueError("bounded Requests timeout must be positive and finite")
    return copied_headers


def check_preparation_inputs(client, request, xor_asset_definition_id):
    """Admit the original closed request graph before invoking its canonical codec.

    This is callback/storage admission, not another codec or identity validator.
    The existing staking schemas and validators remain the sole semantic owners.
    """
    from iroha_python import validator_staking as model
    from iroha_python.numeric_v1 import KotodamaQuantity
    client_state = check_bounded_client(client)
    if client_state["network"] is None:
        raise ValueError("staking preparation requires immutable ToriiClient local_signing_context")
    _text_size(xor_asset_definition_id, "XOR asset definition")
    size = 0

    def visit(value, kind, depth=0):
        nonlocal size
        if depth > 12:
            raise ValueError("bounded staking preparation graph exceeds its depth")
        size += 128
        result = value
        if kind in model._SCHEMAS:
            fields = model._SCHEMAS[kind]
            state = _closed_fields(value, kind, tuple(name for name, _ in fields), "staking value")
            # Retain detached canonical children; no caller can rebind a field
            # or attach a codec callback after admission but before encoding.
            result = kind(*(visit(state[name], child, depth + 1) for name, child in fields))
        elif type(kind) is tuple:
            if kind[0] == "option":
                if value is not None:
                    result = visit(value, kind[1], depth + 1)
            else:
                if type(value) is not tuple or len(value) > kind[2]:
                    raise TypeError("bounded staking preparation requires its bounded tuple")
                result = tuple(visit(item, kind[1], depth + 1) for item in value)
        elif kind == "preparation_operation":
            if type(value) not in model._PREPARATION_OPERATIONS:
                raise TypeError("bounded staking preparation requires an exact operation")
            result = visit(value, type(value), depth + 1)
        elif kind in ("account", "definition", "key"):
            size += 2 * _text_size(value, "staking identity")
        elif kind in ("hash", "bytes32"):
            if type(value) is not bytes or len(value) != 32:
                raise TypeError("bounded staking preparation requires a 32-byte identity")
        elif kind == "quantity":
            state = _closed_fields(value, KotodamaQuantity, ("mantissa", "scale"), "staking quantity")
            _unsigned(state["mantissa"], "quantity mantissa", (1 << 511) - 1)
            _unsigned(state["scale"], "quantity scale", 28)
            result = KotodamaQuantity(state["mantissa"], state["scale"])
            if (result.mantissa, result.scale) != (state["mantissa"], state["scale"]):
                raise ValueError("bounded staking preparation requires canonical quantity fields")
        elif kind == "bool":
            if type(value) is not bool:
                raise TypeError("bounded staking preparation requires an exact flag")
        elif kind in ("lane", "u16", "u64"):
            _unsigned(value, "staking integer", (1 << (32 if kind == "lane" else int(kind[1:]))) - 1)
        else:
            raise TypeError("bounded staking preparation contains unsupported storage")
        if size > _FRAME_LIMIT:
            raise ValueError("bounded staking preparation graph exceeds its envelope bound")
        return result

    frozen_request = visit(request, model.StakingPreparationRequestV1)
    return client_state["timeout"], client_state["network"], frozen_request


def _standard_log_stream(stream):
    # Calling a caller's fileno/flush/close is not admissible. Read exact builtin
    # storage, then call FileIO's descriptor directly; never touch its write lock.
    if type(stream) is not io.TextIOWrapper:
        raise TypeError("bounded alias logging requires a builtin text file stream")
    state = _object_state(stream, "logging stream", 1)
    if state and (tuple(state) != ("mode",) or type(state["mode"]) is not str):
        raise TypeError("bounded alias logging rejects modified stream methods")
    buffer = io.TextIOWrapper.buffer.__get__(stream)
    if type(buffer) not in (io.BufferedWriter, io.BufferedRandom):
        raise TypeError("bounded alias logging requires builtin buffered file storage")
    if _object_state(buffer, "logging buffer", 0):
        raise TypeError("bounded alias logging rejects modified buffer methods")
    raw = type(buffer).raw.__get__(buffer)
    if type(raw) is not io.FileIO:
        raise TypeError("bounded alias logging requires builtin raw file storage")
    raw_state = _object_state(raw, "logging raw file", 1)
    if raw_state:
        if tuple(raw_state) != ("name",):
            raise TypeError("bounded alias logging rejects modified file methods")
        if type(raw_state["name"]) is str:
            _text_size(raw_state["name"], "logging file name")
        else:
            _unsigned(raw_state["name"], "logging file descriptor")
    encoding = io.TextIOWrapper.encoding.__get__(stream)
    errors = io.TextIOWrapper.errors.__get__(stream)
    _text_size(encoding, "logging encoding", 64)
    _text_size(errors, "logging error handler", 64)
    if encoding.lower().replace("-", "") not in ("utf8", "ascii", "latin1", "iso88591"):
        raise TypeError("bounded alias logging requires a builtin text encoding")
    if type(errors) is not str or errors not in ("strict", "backslashreplace", "replace", "ignore", "surrogateescape"):
        raise TypeError("bounded alias logging rejects custom encoding error handlers")
    return _unsigned(io.FileIO.fileno(raw), "logging file descriptor"), encoding, errors


def _standard_log_formatter(formatter):
    if formatter is None:
        formatter = logging._defaultFormatter
    state = _closed_fields(formatter, logging.Formatter, ("_style", "_fmt", "datefmt"), "logging formatter")
    style = _closed_fields(state["_style"], logging.PercentStyle, ("_fmt", "_defaults"), "logging format style")
    _text_size(state["_fmt"], "logging format", 4096)
    _text_size(style["_fmt"], "logging style format", 4096)
    if style["_fmt"] != state["_fmt"] or style["_defaults"] is not None:
        raise TypeError("bounded alias logging rejects modified format style")
    datefmt = state["datefmt"]
    if datefmt is not None:
        _text_size(datefmt, "logging date format", 256)
    # Even a short printf-style width can request an enormous allocation.
    # Admit the standard message formatter; custom layouts are explicit refusals.
    if state["_fmt"] != "%(message)s" or datefmt is not None:
        raise TypeError("bounded alias logging requires the default message formatter")
    return state["_fmt"], ""


def _standard_log_handler(handler):
    kind = type(handler)
    if kind not in (logging.StreamHandler, logging.NullHandler, logging._StderrHandler):
        raise TypeError("bounded alias logging rejects custom handlers")
    fields = ("filters", "_name", "level", "formatter", "_closed", "lock")
    if kind is logging.StreamHandler:
        fields += ("stream",)
    state = _closed_fields(handler, kind, fields, "logging handler")
    if type(state["filters"]) is not list or len(state["filters"]) != 0:
        raise TypeError("bounded alias logging rejects handler filters")
    if state["_name"] is not None:
        _text_size(state["_name"], "logging handler name", 256)
    level = _unsigned(state["level"], "logging handler level", (1 << 31) - 1)
    if type(state["_closed"]) is not bool or state["_closed"]:
        raise TypeError("bounded alias logging requires an open standard handler")
    if kind is logging.NullHandler:
        if state["lock"] is not None or state["formatter"] is not None:
            raise TypeError("bounded alias logging rejects modified null handlers")
        return None
    if type(state["lock"]) is not type(threading.RLock()):
        raise TypeError("bounded alias logging rejects custom handler locks")
    fmt, datefmt = _standard_log_formatter(state["formatter"])
    stream = sys.stderr if kind is logging._StderrHandler else state["stream"]
    fd, encoding, errors = _standard_log_stream(stream)
    return (fd, level, fmt, datefmt, encoding, errors)


def _standard_logging(logger):
    if logging._logRecordFactory is not logging.LogRecord:
        raise TypeError("bounded alias logging rejects custom record factories")
    manager = logging.Logger.manager
    manager_state = _closed_fields(manager, logging.Manager,
        ("root", "_disable", "emittedNoHandlerWarning", "loggerDict", "loggerClass", "logRecordFactory"), "logging manager")
    disable = _unsigned(manager_state["_disable"], "logging disable level", (1 << 31) - 1)
    if manager_state["loggerClass"] is not None or manager_state["logRecordFactory"] is not None:
        raise TypeError("bounded alias logging rejects custom manager factories")
    nodes = []
    seen = set()
    current = logger
    while current is not None:
        if len(nodes) >= 16 or id(current) in seen or type(current) not in (logging.Logger, logging.RootLogger):
            raise TypeError("bounded alias logging requires a finite standard logger chain")
        seen.add(id(current))
        fields = ("filters", "name", "level", "parent", "propagate", "handlers", "disabled", "_cache")
        raw = _object_state(current, "logger", 9)
        if "manager" in raw:
            fields += ("manager",)
            if raw["manager"] is not manager:
                raise TypeError("bounded alias logging rejects custom managers")
        state = _closed_fields(current, type(current), fields, "logger")
        _text_size(state["name"], "logger name", 256)
        _unsigned(state["level"], "logger level", (1 << 31) - 1)
        if type(state["filters"]) is not list or len(state["filters"]) != 0:
            raise TypeError("bounded alias logging rejects logger filters")
        if type(state["propagate"]) is not bool or type(state["disabled"]) is not bool:
            raise TypeError("bounded alias logging requires exact logger flags")
        if type(state["handlers"]) is not list or len(state["handlers"]) > 16:
            raise TypeError("bounded alias logging requires bounded builtin handler lists")
        for level, enabled in _mapping(state["_cache"], "logger cache", 128, ordered=False):
            _unsigned(level, "logging cached level", (1 << 31) - 1)
            if type(enabled) is not bool:
                raise TypeError("bounded alias logging rejects altered logger cache values")
        nodes.append(state)
        current = state["parent"]
    if not nodes:
        raise TypeError("bounded alias logging requires a standard logger")
    effective = next((state["level"] for state in nodes if state["level"]), 0)
    enabled = not nodes[0]["disabled"] and disable < logging.WARNING and logging.WARNING >= effective
    if logging.WARNING in nodes[0]["_cache"] and nodes[0]["_cache"][logging.WARNING] != enabled:
        raise TypeError("bounded alias logging rejects inconsistent logger cache")
    sinks = []
    found = 0
    for state in nodes:
        for handler in state["handlers"]:
            found += 1
            if found > 16:
                raise ValueError("bounded alias logging exceeds its handler limit")
            sink = _standard_log_handler(handler)
            if sink is not None:
                sinks.append(sink)
        if not state["propagate"]:
            break
    if found == 0:
        if logging.lastResort is None:
            # Without lastResort, logging can write its one-time diagnostic to
            # stderr. That parent-dependent mutable state is not an admitted graph.
            raise TypeError("bounded alias logging requires the standard last-resort handler")
        sink = _standard_log_handler(logging.lastResort)
        if sink is not None:
            sinks.append(sink)
    return nodes[0]["name"], enabled, sinks


def _alias_snapshot(policy, warning_hook, logger):
    if policy is None:
        if warning_hook is not None or logger is not None:
            raise TypeError("bounded alias configuration requires an explicit policy")
        return [], "", False, []
    from iroha_python.sorafs import SorafsAliasPolicy
    if warning_hook is not None:
        raise TypeError("bounded staking preparation does not support custom alias warning callbacks")
    state = _closed_fields(policy, SorafsAliasPolicy, _POLICY_FIELDS, "alias policy")
    values = [_unsigned(state[field], "alias policy") for field in _POLICY_FIELDS]
    # Re-run the canonical policy constructor, never methods on supplied objects.
    SorafsAliasPolicy(**dict(zip(_POLICY_FIELDS, values, strict=True)))
    name, enabled, sinks = _standard_logging(logger)
    return values, name, enabled, sinks


def _evaluation_size(values):
    if type(values) is not list or len(values) > 1:
        raise TypeError("bounded alias outcome requires at most one evaluation")
    size = 16
    for row in values:
        if type(row) is not tuple or len(row) != 8:
            raise TypeError("bounded alias evaluation requires its exact tuple")
        size += _text_size(row[0], "alias state", 64) + _text_size(row[1], "alias status", 64) + 96
        for index in (2, 7):
            if type(row[index]) is not bool:
                raise TypeError("bounded alias evaluation requires exact flags")
        for index in (3, 4, 5):
            _unsigned(row[index], "alias evaluation")
        if type(row[6]) is not list or len(row[6]) > 1:
            raise TypeError("bounded alias expiry requires at most one integer")
        for value in row[6]:
            _unsigned(value, "alias expiry")
    return size


def _alias_frame_size(value, request):
    if not request:
        return _evaluation_size(value["alias_evaluation"])
    policy = value["alias_policy"]
    if type(policy) is not list or len(policy) not in (0, 8):
        raise TypeError("bounded alias policy requires its exact field count")
    for item in policy:
        _unsigned(item, "alias policy")
    if type(value["log_enabled"]) is not bool:
        raise TypeError("bounded alias logging requires an exact enabled flag")
    sinks = value["log_sinks"]
    if type(sinks) is not list or len(sinks) > 16:
        raise TypeError("bounded alias logging requires a bounded sink list")
    size = 128
    for sink in sinks:
        if type(sink) is not tuple or len(sink) != 6:
            raise TypeError("bounded alias logging requires its exact sink tuple")
        _unsigned(sink[0], "logging sink descriptor", (1 << 31) - 1)
        _unsigned(sink[1], "logging sink level", (1 << 31) - 1)
        size += 128 + _text_size(sink[2], "logging format", 4096)
        for text in sink[3:]:
            size += _text_size(text, "logging setting", 256)
        if sink[2] != "%(message)s" or sink[3] != "":
            raise TypeError("bounded alias logging requires the default message formatter")
    return size


def _enforce_worker_alias(response, request):
    from iroha_python.sorafs import SorafsAliasPolicy, enforce_alias_policy
    if not request["alias_policy"]:
        return []
    # Reconstruct only the admitted standard graph. All formatting, writes,
    # flushes, proof evaluation and handler cleanup occur in the owned worker.
    logger = logging.Logger(request["log_name"], logging.WARNING)
    logger.propagate = False
    logger.disabled = not request["log_enabled"]
    streams = []
    try:
        for fd, level, fmt, datefmt, encoding, errors in request["log_sinks"]:
            stream = os.fdopen(os.dup(fd), "w", encoding=encoding, errors=errors)
            streams.append(stream)
            handler = logging.StreamHandler(stream)
            handler.setLevel(level)
            handler.setFormatter(logging.Formatter(fmt, datefmt or None))
            logger.addHandler(handler)
        if not logger.handlers:
            logger.addHandler(logging.NullHandler())
        evaluation = enforce_alias_policy(response,
            policy=SorafsAliasPolicy(**dict(zip(_POLICY_FIELDS, request["alias_policy"], strict=True))),
            logger=logger)
        if evaluation is None:
            return []
        return [tuple(getattr(evaluation, field) if field != "expires_in_seconds" else
                      ([] if evaluation.expires_in_seconds is None else [evaluation.expires_in_seconds])
                      for field in _EVALUATION_FIELDS)]
    finally:
        for handler in logger.handlers:
            handler.close()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                # Standard logging handles sink I/O failures internally. Cleanup
                # must not turn an already handled write error into proof failure.
                pass


def _pair_list_size(value, label):
    if type(value) is not list or len(value) > _PAIRS_LIMIT:
        raise TypeError(f"bounded Requests {label} requires a bounded pair list")
    size = 10
    text_size = 0
    for row in value:
        if type(row) is not tuple or len(row) != 2:
            raise TypeError(f"bounded Requests {label} requires exact pair tuples")
        row_size = _text_size(row[0], label) + _text_size(row[1], label)
        text_size += row_size
        if text_size > _HEADERS_LIMIT:
            raise ValueError(f"bounded Requests {label} exceeds its byte limit")
        size += row_size + 32
    return size


def _frame_bound(value, adapter):
    if type(value) is not dict:
        raise TypeError("bounded Requests IPC requires an exact record")
    request = adapter is _REQUEST
    if not request and adapter is not _RESPONSE:
        raise TypeError("bounded Requests IPC requires its closed schema")
    text_fields = ({"method": _METHOD_LIMIT, "url": _HEADERS_LIMIT,
                    "ca_path": _HEADERS_LIMIT, "media_type": _MEDIA_LIMIT, "log_name": 256} if request else
                   {"request_method": _METHOD_LIMIT, "request_url": _HEADERS_LIMIT, "error_message": _HEADERS_LIMIT})
    pair_fields = ("headers", "session_headers", "session_params", "proxies") if request else ("headers", "request_headers")
    byte_fields = {"body": 64 * 1024} if request else {"body": _BODY_LIMIT, "request_body": 64 * 1024}
    integer_fields = {"verify": 2, "timeout_ns": (1 << 64) - 1, "deadline_ns": (1 << 64) - 1, "max_body": _BODY_LIMIT} if request else {"error": 5, "status": 599}
    fields = set(text_fields) | set(pair_fields) | set(byte_fields) | set(integer_fields)
    if request:
        fields.update(("trust_env", "cert", "alias_policy", "log_enabled", "log_sinks"))
    else:
        fields.add("alias_evaluation")
    rows = _mapping(value, "IPC record", len(fields), ordered=False)
    if len(value) != len(fields):
        raise ValueError("bounded Requests IPC record fields differ")
    for key, _ in rows:
        _text_size(key, "IPC field", 64)
        if key not in fields:
            raise ValueError("bounded Requests IPC record fields differ")
    # Conservative upper bound includes maximum length-prefix/field overhead,
    # established before the full canonical encoder can allocate its output.
    size = 48 + 16 * len(fields) + _alias_frame_size(value, request)
    for key, maximum in text_fields.items():
        size += _text_size(value[key], key, maximum) + 10
    for key in pair_fields:
        size += _pair_list_size(value[key], key)
    for key, maximum in byte_fields.items():
        item = value[key]
        if type(item) is not bytes:
            raise TypeError("bounded Requests IPC requires exact immutable bytes")
        if len(item) > maximum:
            raise ValueError("bounded Requests IPC body exceeds its byte limit")
        size += len(item) + 10
    for key, maximum in integer_fields.items():
        item = value[key]
        if type(item) is not int or item < 0 or item > maximum:
            raise ValueError("bounded Requests IPC integer exceeds its range")
        size += 8
    if request:
        if type(value["trust_env"]) is not bool:
            raise TypeError("bounded Requests trust_env must be an exact bool")
        cert = value["cert"]
        if type(cert) is not list or len(cert) > 2:
            raise TypeError("bounded Requests certificates require at most two paths")
        size += 10 + sum(_text_size(path, "certificate") + 10 for path in cert)
    if size > _FRAME_LIMIT:
        raise ValueError("bounded Requests IPC envelope exceeds its byte limit")


def _frame(value, adapter, schema):
    _frame_bound(value, adapter)
    result = encode(value, schema, adapter, flags=COMPACT_LEN)
    if len(result) > _FRAME_LIMIT:
        raise ValueError("bounded Requests IPC frame exceeds its byte limit")
    return result


def _unframe(value, adapter, schema):
    if type(value) is not bytes or len(value) > _FRAME_LIMIT:
        raise ValueError("bounded Requests IPC frame exceeds its byte limit")
    header, _ = NoritoHeader.decode(value, expected_schema_hash=schema.hash_bytes(), expected_flags=COMPACT_LEN)
    if header.compression != 0 or len(value) != 40 + header.payload_length:
        raise ValueError("bounded Requests IPC requires exact uncompressed framing")
    result = decode(value, adapter, schema=schema)
    if _frame(result, adapter, schema) != value:
        raise ValueError("bounded Requests IPC frame is not canonical")
    return result


def _snapshot(session, method, url, headers, body, timeout, deadline_ns, max_body, media_type, alias=((), "", False, ())):
    state = _standard_session(session)
    _text_size(method, "method", _METHOD_LIMIT)
    _text_size(url, "URL")
    _text_size(media_type, "media type", _MEDIA_LIMIT)
    if type(body) is not bytes or len(body) > 64 * 1024:
        raise ValueError("bounded Requests requires at most 64 KiB of immutable request bytes")
    if type(timeout) not in (int, float) or (type(timeout) is int and timeout.bit_length() > 64) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("bounded Requests timeout must be positive and finite")
    if type(max_body) is not int or not 0 <= max_body <= _BODY_LIMIT:
        raise ValueError("bounded Requests body limit is invalid")
    # No Requests preparation or environment lookup may happen in the parent:
    # trust_env can synchronously read a NETRC FIFO or block in proxy discovery.
    if type(state["trust_env"]) is not bool:
        raise TypeError("bounded Requests trust_env must be an exact bool")
    verify = state["verify"]
    if type(verify) not in (str, bool):
        raise TypeError("bounded Requests TLS verification must be a bool or CA path")
    cert = state["cert"]
    if cert is None:
        cert = []
    elif type(cert) is str:
        cert = [cert]
    elif type(cert) is tuple and len(cert) == 2 and all(type(item) is str for item in cert):
        cert = list(cert)
    else:
        raise TypeError("bounded Requests client certificate must be a path or exact path pair")
    if type(verify) is str:
        _text_size(verify, "CA path")
    for path in cert:
        _text_size(path, "certificate path")
    values = {
        "method": method, "url": url, "headers": _pairs(headers, "request headers"),
        "body": body, "session_headers": _pairs(state["headers"], "Session headers"),
        "session_params": _pairs(state["params"], "Session parameters"),
        "trust_env": state["trust_env"], "proxies": _pairs(state["proxies"], "proxies"),
        "verify": 2 if type(verify) is str else int(verify), "ca_path": verify if type(verify) is str else "",
        "cert": cert, "timeout_ns": int(min(timeout, ((1 << 64) - 1) // 1_000_000_000) * 1_000_000_000),
        "deadline_ns": deadline_ns, "max_body": max_body, "media_type": media_type,
        "alias_policy": list(alias[0]), "log_name": alias[1],
        "log_enabled": alias[2], "log_sinks": list(alias[3]),
    }
    # Copy only the environment already visible to this process. Requests resolves
    # it once in the worker; caller headers/body are never copied into environment.
    return _frame(values, _REQUEST, _REQUEST_SCHEMA), dict(os.environ)


def _remaining(deadline_ns):
    if type(deadline_ns) is not int or not 0 < deadline_ns < (1 << 64):
        raise ValueError("absolute Requests deadline must be an exact positive u64")
    remaining = (deadline_ns - time.monotonic_ns()) / 1_000_000_000
    if remaining <= 0:
        raise requests.Timeout("absolute Requests operation deadline expired")
    return remaining


def _retire(process):
    # Only this operation's exact child is signalled. Closing parent pipes does
    # not interrupt Requests; process termination owns that socket cleanup.
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            stream.close()
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1.0)
    else:
        process.wait()


def _exchange(frame, deadline_ns, environment, inherited_fds=()):
    if os.name != "posix":
        raise RuntimeError("absolute Requests deadline owner requires POSIX private pipes")
    _remaining(deadline_ns)
    if not os.path.isabs(__file__):
        raise RuntimeError("bounded Requests owner requires an absolute installed module path")
    process = subprocess.Popen(
        [sys.executable, "-I", __file__, "--worker"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        close_fds=True, bufsize=0, env=environment, pass_fds=inherited_fds,
    )
    try:
        assert process.stdin is not None and process.stdout is not None
        output = bytearray()
        sent = 0
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE)
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                for key, events in selector.select(_remaining(deadline_ns)):
                    _remaining(deadline_ns)
                    if events & selectors.EVENT_WRITE:
                        written = os.write(key.fd, frame[sent:sent + 8192])
                        sent += written
                        if sent == len(frame):
                            selector.unregister(key.fileobj)
                            process.stdin.close()
                    else:
                        chunk = os.read(key.fd, min(8192, _FRAME_LIMIT + 1 - len(output)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > _FRAME_LIMIT:
                                raise ValueError("bounded Requests worker output exceeds its byte limit")
        process.wait(timeout=_remaining(deadline_ns))
        if process.returncode != 0:
            raise requests.ConnectionError("bounded Requests worker did not complete")
        return _unframe(bytes(output), _RESPONSE, _RESPONSE_SCHEMA)
    except subprocess.TimeoutExpired as error:
        raise requests.Timeout("absolute Requests operation deadline expired") from error
    finally:
        _retire(process)


def send_bounded_request(*, session, method, url, headers, body, timeout, deadline_ns,
                         max_body, media_type, alias_policy=None, alias_warning_hook=None, alias_logger=None):
    """Send once through Requests, return a finite closed response, reap the child.

    The deadline includes request preparation and worker startup/HTTP/body IPC.
    Cleanup may add at most the owned-child termination/join grace (1.2 s).
    Unsupported Session behavior is rejected before a worker or socket exists.
    """
    if os.name != "posix":
        raise RuntimeError("absolute Requests deadline owner requires POSIX private pipes")
    _remaining(deadline_ns)
    alias = _alias_snapshot(alias_policy, alias_warning_hook, alias_logger)
    # Admit the complete request before duplicating sinks. Duplicates freeze the
    # exact original open file descriptions; the parent never writes or flushes.
    frame, environment = _snapshot(session, method, url, headers, body, timeout, deadline_ns, max_body, media_type, alias)
    inherited = []
    try:
        sinks = []
        for sink in alias[3]:
            fd = os.dup(sink[0])
            inherited.append(fd)
            sinks.append((fd,) + sink[1:])
        if sinks:
            request = _unframe(frame, _REQUEST, _REQUEST_SCHEMA)
            request["log_sinks"] = sinks
            frame = _frame(request, _REQUEST, _REQUEST_SCHEMA)
        result = _exchange(frame, deadline_ns, environment, tuple(inherited))
    finally:
        for fd in inherited:
            os.close(fd)
    _remaining(deadline_ns)
    if result["error"] == 1:
        raise requests.Timeout("absolute Requests operation deadline expired")
    if result["error"] == 2:
        raise requests.ConnectionError("bounded Requests transport failed")
    if result["error"] == 4:
        from iroha_python.sorafs import SorafsAliasError
        cause = SorafsAliasError(result["error_message"])
        raise RuntimeError(f"failed to validate SoraFS alias proof: {cause}") from cause
    if result["error"] == 5:
        raise ValueError(result["error_message"])
    if result["error"] != 0:
        raise ValueError("bounded Requests rejected response framing or body limits")
    if len(result["body"]) > max_body:
        raise ValueError("bounded Requests response exceeds its body limit")
    if not 100 <= result["status"] <= 599:
        raise ValueError("bounded Requests response status is invalid")
    _pairs(dict(result["headers"]), "response headers")
    prepared = requests.PreparedRequest()
    prepared.method = result["request_method"]
    prepared.url = result["request_url"]
    prepared.headers = requests.structures.CaseInsensitiveDict(result["request_headers"])
    prepared.body = result["request_body"]
    if (prepared.method != method.upper() or prepared.body != body
            or len(prepared.url) > _HEADERS_LIMIT):
        raise ValueError("bounded Requests prepared request metadata differs")
    _pairs(prepared.headers, "prepared request headers")
    response = requests.Response()
    response.status_code = result["status"]
    response.headers = requests.structures.CaseInsensitiveDict(result["headers"])
    response.url = prepared.url
    response.request = prepared
    response._content = result["body"]
    response._content_consumed = True
    response._iroha_alias_evaluation = None
    if result["alias_evaluation"]:
        from iroha_python.sorafs import SorafsAliasEvaluation
        values = list(result["alias_evaluation"][0])
        values[6] = values[6][0] if values[6] else None
        response._iroha_alias_evaluation = SorafsAliasEvaluation(**dict(zip(_EVALUATION_FIELDS, values, strict=True)))
    return response


def _empty_result(error=0):
    return {"error": error, "status": 0, "headers": [], "body": b"",
            "request_method": "", "request_url": "", "request_headers": [], "request_body": b"",
            "alias_evaluation": [], "error_message": ""}


def _prepare_request(session, request):
    """Perform the original Requests preparation and environment lookup exactly once."""
    session.headers = requests.structures.CaseInsensitiveDict(request["session_headers"])
    session.params = dict(request["session_params"])
    session.trust_env = request["trust_env"]
    session.proxies = dict(request["proxies"])
    session.verify = request["ca_path"] if request["verify"] == 2 else bool(request["verify"])
    cert = request["cert"]
    session.cert = None if not cert else cert[0] if len(cert) == 1 else tuple(cert)
    prepared = session.prepare_request(requests.Request(request["method"], request["url"],
        headers=dict(request["headers"]), data=request["body"]))
    # URL expansion from Session params/percent encoding is bounded before any
    # adapter dispatch, not merely when returning prepared metadata afterward.
    _text_size(prepared.url, "prepared URL")
    settings = session.merge_environment_settings(prepared.url, {}, True, None, None)
    if type(prepared.body) is not bytes or prepared.body != request["body"]:
        raise ValueError("bounded Requests preparation changed immutable request bytes")
    return prepared, settings


def _worker():
    request_frame = sys.stdin.buffer.read(_FRAME_LIMIT + 1)
    request = _unframe(request_frame, _REQUEST, _REQUEST_SCHEMA)
    result = _empty_result()
    try:
        _remaining(request["deadline_ns"])
        with requests.Session() as session:
            prepared, settings = _prepare_request(session, request)
            _remaining(request["deadline_ns"])
            result.update(request_method=prepared.method, request_url=prepared.url,
                          request_headers=_pairs(prepared.headers, "prepared request headers"),
                          request_body=prepared.body)
            # Session.send consumes redirect bodies while preparing response._next,
            # even with allow_redirects=False. Dispatch through Requests' own
            # standard adapter so every response body belongs to our bound.
            with session.get_adapter(prepared.url).send(prepared, stream=True,
                              timeout=min(request["timeout_ns"] / 1_000_000_000, _remaining(request["deadline_ns"])),
                              proxies=settings["proxies"], verify=settings["verify"], cert=settings["cert"]) as response:
                result["status"] = response.status_code
                result["headers"] = _pairs(response.headers, "response headers")
                if response.status_code == 200 and response.headers.get("Content-Type", "").strip().lower() != request["media_type"]:
                    raise ValueError("unexpected response media type")
                if "Set-Cookie" in response.headers:
                    raise ValueError("bounded observation rejects response cookie mutation")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise ValueError("compressed responses cannot satisfy the decoded byte bound")
                declared = response.headers.get("Content-Length")
                if declared is not None and (not declared.isascii() or not declared.isdecimal()
                        or (len(declared) > 1 and declared.startswith("0"))
                        or len(declared) > len(str(request["max_body"])) or int(declared) > request["max_body"]):
                    raise ValueError("invalid response Content-Length")
                body = bytearray()
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=False):
                    _remaining(request["deadline_ns"])
                    if len(chunk) > request["max_body"] - len(body):
                        raise ValueError("response body exceeds its byte bound")
                    body.extend(chunk)
                if declared is not None and int(declared) != len(body):
                    raise ValueError("response Content-Length mismatch")
                result["body"] = bytes(body)
                if request["alias_policy"]:
                    from iroha_python.sorafs import SorafsAliasError
                    try:
                        result["alias_evaluation"] = _enforce_worker_alias(response, request)
                    except SorafsAliasError as error:
                        result = _empty_result(4)
                        result["error_message"] = str(error)
                    except (ValueError, TypeError) as error:
                        result = _empty_result(5)
                        result["error_message"] = str(error)
    except requests.Timeout:
        result = _empty_result(1)
    except requests.RequestException:
        result = _empty_result(2)
    except (ValueError, TypeError):
        result = _empty_result(3)
    sys.stdout.buffer.write(_frame(result, _RESPONSE, _RESPONSE_SCHEMA))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    if sys.argv[1:] != ["--worker"]:
        raise SystemExit(2)
    _worker()

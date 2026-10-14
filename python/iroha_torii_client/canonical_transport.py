"""One-owner Requests preparation and dispatch for canonical authentication."""

from __future__ import annotations

from typing import Any, Callable, Mapping, MutableMapping, Optional
from urllib.parse import urlsplit

import requests

from .canonical_request_v1 import require_zero_retry_adapter

OPERATOR_FORBIDDEN_AUTH_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookie2",
        "x-api-token",
        "x-iroha-account",
        "x-iroha-signature",
        "x-iroha-timestamp-ms",
        "x-iroha-nonce",
        "x-iroha-witness",
        "x-iroha-iso-profile",
        "x-iroha-operator-public-key",
        "x-iroha-operator-timestamp-ms",
        "x-iroha-operator-nonce",
        "x-iroha-operator-signature",
    }
)


class CanonicalRequestHeaderPlan(dict[str, str]):
    """Base headers plus signer state deferred until Requests fixes the target."""

    def __init__(
        self,
        headers: Mapping[str, str],
        canonical_auth: Any,
        *,
        reject_ambient_auth: bool = False,
    ) -> None:
        super().__init__(headers)
        self.canonical_auth = canonical_auth
        self.reject_ambient_auth = reject_ambient_auth


class OperatorRequestHeaderPlan(dict[str, str]):
    """Base headers plus operator signer state deferred until preparation."""

    def __init__(self, headers: Mapping[str, str], context: Any) -> None:
        super().__init__(headers)
        self.context = context


class _NoAmbientAuth(requests.auth.AuthBase):
    """Truthful no-op auth that prevents Requests from consulting netrc."""

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        return request


_NO_AMBIENT_AUTH = _NoAmbientAuth()


def _is_forbidden_auth_header(name: Any) -> bool:
    normalized = str(name).lower()
    return (
        normalized in OPERATOR_FORBIDDEN_AUTH_HEADERS
        or normalized.startswith("x-iroha-")
    )


def _validate_credential_exclusive_transport(
    *,
    session: requests.Session,
    url: str,
    headers: Mapping[str, str],
    stream: bool,
) -> None:
    if getattr(session, "auth", None) is not None:
        raise ValueError("credential-exclusive requests reject Session.auth")
    for context, source in (
        ("Session.headers", getattr(session, "headers", {})),
        ("request headers", headers),
    ):
        if not isinstance(source, Mapping):
            raise TypeError(f"credential-exclusive requests require mapping {context}")
        for name in source:
            if _is_forbidden_auth_header(name):
                raise ValueError(
                    "credential-exclusive requests reject authentication header "
                    f"{name} from {context}"
                )
    cookies = getattr(session, "cookies", None)
    if cookies is not None:
        try:
            if len(cookies) != 0:
                raise ValueError("credential-exclusive requests reject Session.cookies")
        except TypeError as exc:
            raise TypeError(
                "credential-exclusive requests require inspectable Session.cookies"
            ) from exc
    session_proxies = getattr(session, "proxies", {})
    if not isinstance(session_proxies, Mapping):
        raise TypeError("credential-exclusive requests require mapping Session.proxies")
    try:
        settings = session.merge_environment_settings(
            url,
            {},
            stream,
            None,
            None,
        )
    except AttributeError as exc:
        raise ValueError(
            "credential-exclusive requests require inspectable transport settings"
        ) from exc
    if not isinstance(settings, dict):
        raise TypeError(
            "credential-exclusive request transport settings must be a dictionary"
        )
    proxies = settings.get("proxies", {})
    if not isinstance(proxies, Mapping):
        raise TypeError("credential-exclusive requests require mapping proxy settings")
    configured_proxy = requests.utils.select_proxy(url, session_proxies)
    selected_proxy = requests.utils.select_proxy(url, proxies)
    for proxy in (configured_proxy, selected_proxy):
        if proxy is None or proxy == "":
            continue
        if not isinstance(proxy, str):
            raise TypeError("credential-exclusive requests require string proxy URLs")
        parsed_proxy = urlsplit(proxy)
        if parsed_proxy.username is not None or parsed_proxy.password is not None:
            raise ValueError("credential-exclusive requests reject proxy authentication")
    if selected_proxy != configured_proxy:
        raise ValueError(
            "credential-exclusive requests reject ambient environment proxies"
        )


def _merge_transport_settings(
    session: requests.Session,
    prepared: requests.PreparedRequest,
    *,
    stream: bool,
) -> Mapping[str, Any]:
    try:
        settings = session.merge_environment_settings(
            prepared.url,
            {},
            stream,
            None,
            None,
        )
    except AttributeError as exc:
        raise ValueError(
            "canonical requests require a verifiable prepared-request transport"
        ) from exc
    if not isinstance(settings, dict):
        raise TypeError("canonical request transport settings must be a dictionary")
    return settings


def _validate_operator_prepared_transport(
    *,
    session: requests.Session,
    prepared: requests.PreparedRequest,
    settings: Mapping[str, Any],
) -> None:
    for name in prepared.headers:
        if str(name).lower() in OPERATOR_FORBIDDEN_AUTH_HEADERS:
            raise ValueError(
                "operator GETs reject prepared transport authentication "
                f"header {name}"
            )
    proxies = settings.get("proxies", {})
    session_proxies = getattr(session, "proxies", {})
    if not isinstance(proxies, Mapping) or not isinstance(session_proxies, Mapping):
        raise TypeError("operator GETs require mapping proxy settings")
    selected_proxy = requests.utils.select_proxy(prepared.url, proxies)
    if selected_proxy is None or selected_proxy == "":
        return
    if not isinstance(selected_proxy, str):
        raise TypeError("operator GETs require string proxy URLs")
    configured_proxy = requests.utils.select_proxy(prepared.url, session_proxies)
    if selected_proxy != configured_proxy:
        raise ValueError("operator GETs reject ambient environment proxies")
    parsed_proxy = urlsplit(selected_proxy)
    if parsed_proxy.username is not None or parsed_proxy.password is not None:
        raise ValueError("operator GETs reject proxy authentication")


def send_request(
    *,
    session: requests.Session,
    base_url: str,
    method: str,
    path: str,
    params: Optional[Mapping[str, Any]],
    headers: Optional[MutableMapping[str, str]],
    data: Optional[bytes],
    stream: bool,
    allow_retry: bool,
    allow_redirects: bool,
    timeout: Optional[float],
    build_headers: Callable[..., dict[str, str]],
    build_operator_headers: Callable[..., dict[str, str]],
) -> requests.Response:
    """Dispatch unsigned requests normally and signed requests through one preparation."""

    url = f"{base_url}{path}"
    if not isinstance(
        headers,
        (CanonicalRequestHeaderPlan, OperatorRequestHeaderPlan),
    ):
        if not allow_retry:
            require_zero_retry_adapter(session=session, url=url)
        return session.request(
            method,
            url,
            params=params,
            headers=headers,
            data=data,
            stream=stream,
            allow_redirects=allow_redirects,
            timeout=timeout,
        )
    if allow_retry or allow_redirects:
        raise ValueError("canonical requests must disable redirects and retries")
    reject_ambient_auth = bool(
        isinstance(headers, CanonicalRequestHeaderPlan)
        and headers.reject_ambient_auth
    )
    if reject_ambient_auth:
        _validate_credential_exclusive_transport(
            session=session,
            url=url,
            headers=headers,
            stream=stream,
        )
    request = requests.Request(
        method,
        url,
        params=params,
        headers=dict(headers),
        data=data,
        auth=_NO_AMBIENT_AUTH if reject_ambient_auth else None,
    )
    try:
        prepared = session.prepare_request(request)
    except AttributeError as exc:
        raise ValueError(
            "canonical requests require a verifiable prepared-request transport"
        ) from exc
    prepared_url = prepared.url
    if not isinstance(prepared_url, str):
        raise ValueError("canonical request preparation returned no exact URL")
    if reject_ambient_auth:
        for name in prepared.headers:
            if _is_forbidden_auth_header(name):
                raise ValueError(
                    f"canonical request preparation introduced ambient {name}"
                )
    prepared_body = prepared.body
    if prepared_body is None:
        body = b""
    elif isinstance(prepared_body, (bytes, bytearray, memoryview)):
        body = bytes(prepared_body)
    else:
        raise TypeError("canonical request body must remain exact bytes after preparation")
    if isinstance(headers, CanonicalRequestHeaderPlan):
        auth = headers.canonical_auth
        signed_headers = build_headers(
            network_id=auth.network_id,
            account_id=auth.account_id,
            signer=auth.signer,
            method=method,
            path=prepared.path_url,
            body=body,
            timestamp_ms=auth.timestamp_ms,
            nonce=auth.nonce,
        )
    else:
        environment_settings = _merge_transport_settings(
            session,
            prepared,
            stream=stream,
        )
        _validate_operator_prepared_transport(
            session=session,
            prepared=prepared,
            settings=environment_settings,
        )
        signed_headers = build_operator_headers(
            headers.context,
            method,
            prepared.path_url,
            body,
        )
    prepared.headers.update(signed_headers)
    require_zero_retry_adapter(session=session, url=prepared_url)
    try:
        # Canonical authentication signs the prepared target and headers.  Do not
        # consult trust_env after that audit: environment proxies can inject
        # Proxy-Authorization and environment CA variables can silently replace
        # the caller's TLS policy.  Snapshot only the explicit Session settings.
        settings: dict[str, Any] = {
            "stream": stream,
            "verify": session.verify,
            "cert": session.cert,
            "proxies": dict(session.proxies),
        }
        return session.send(
            prepared,
            allow_redirects=False,
            timeout=timeout,
            **settings,
        )
    except AttributeError as exc:
        raise ValueError(
            "canonical requests require a verifiable prepared-request transport"
        ) from exc

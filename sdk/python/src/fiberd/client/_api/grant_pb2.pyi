from google.protobuf import empty_pb2 as _empty_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Mapping as _Mapping, Optional as _Optional, Union as _Union

ATTACH: CloneKind
BEST_EFFORT: Durability
CREATE: CloneKind
DEFERRED_FALLBACK: MissCode
DESCRIPTOR: _descriptor.FileDescriptor
DIRECT: EndpointMode
DURABILITY_UNSPECIFIED: Durability
FIBER_BASIC: Tier
FIBER_CHECKPOINT: Tier
FIBER_SNAPSHOT: Tier
FIBER_WARM: Tier
HANDOFF: EndpointMode
ISOLATION_UNSPECIFIED: Isolation
RESUME: CloneKind
SHED: MissCode
SYNC: Durability
TIER_UNSPECIFIED: Tier
TRUSTED: Isolation
UNTRUSTED: Isolation

class CapacityGrant(_message.Message):
    __slots__ = ["audience", "device_budget", "fibers", "grant_uid", "issuer", "lease_expiry", "min_tier", "policy", "template_digest", "tenant", "w_budget_bytes"]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    DEVICE_BUDGET_FIELD_NUMBER: _ClassVar[int]
    FIBERS_FIELD_NUMBER: _ClassVar[int]
    GRANT_UID_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    LEASE_EXPIRY_FIELD_NUMBER: _ClassVar[int]
    MIN_TIER_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    TENANT_FIELD_NUMBER: _ClassVar[int]
    W_BUDGET_BYTES_FIELD_NUMBER: _ClassVar[int]
    audience: str
    device_budget: DeviceBudget
    fibers: FiberLimits
    grant_uid: str
    issuer: str
    lease_expiry: _timestamp_pb2.Timestamp
    min_tier: Tier
    policy: Policy
    template_digest: str
    tenant: str
    w_budget_bytes: int
    def __init__(self, grant_uid: _Optional[str] = ..., issuer: _Optional[str] = ..., audience: _Optional[str] = ..., template_digest: _Optional[str] = ..., tenant: _Optional[str] = ..., fibers: _Optional[_Union[FiberLimits, _Mapping]] = ..., w_budget_bytes: _Optional[int] = ..., min_tier: _Optional[_Union[Tier, str]] = ..., lease_expiry: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., policy: _Optional[_Union[Policy, _Mapping]] = ..., device_budget: _Optional[_Union[DeviceBudget, _Mapping]] = ...) -> None: ...

class CloneRequest(_message.Message):
    __slots__ = ["deadline", "grant_jwt", "payload", "session"]
    DEADLINE_FIELD_NUMBER: _ClassVar[int]
    GRANT_JWT_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    SESSION_FIELD_NUMBER: _ClassVar[int]
    deadline: _timestamp_pb2.Timestamp
    grant_jwt: str
    payload: bytes
    session: str
    def __init__(self, grant_jwt: _Optional[str] = ..., session: _Optional[str] = ..., deadline: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., payload: _Optional[bytes] = ...) -> None: ...

class CloneResponse(_message.Message):
    __slots__ = ["endpoint", "fence", "fiber_id", "kind", "routing_key", "server_key_sha256"]
    ENDPOINT_FIELD_NUMBER: _ClassVar[int]
    FENCE_FIELD_NUMBER: _ClassVar[int]
    FIBER_ID_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    ROUTING_KEY_FIELD_NUMBER: _ClassVar[int]
    SERVER_KEY_SHA256_FIELD_NUMBER: _ClassVar[int]
    endpoint: str
    fence: Fence
    fiber_id: str
    kind: CloneKind
    routing_key: str
    server_key_sha256: str
    def __init__(self, fiber_id: _Optional[str] = ..., endpoint: _Optional[str] = ..., fence: _Optional[_Union[Fence, _Mapping]] = ..., kind: _Optional[_Union[CloneKind, str]] = ..., routing_key: _Optional[str] = ..., server_key_sha256: _Optional[str] = ...) -> None: ...

class DeviceBudget(_message.Message):
    __slots__ = ["bytes"]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    CLASS_FIELD_NUMBER: _ClassVar[int]
    bytes: int
    def __init__(self, bytes: _Optional[int] = ..., **kwargs) -> None: ...

class Fence(_message.Message):
    __slots__ = ["epoch", "grant_uid", "seq"]
    EPOCH_FIELD_NUMBER: _ClassVar[int]
    GRANT_UID_FIELD_NUMBER: _ClassVar[int]
    SEQ_FIELD_NUMBER: _ClassVar[int]
    epoch: int
    grant_uid: str
    seq: int
    def __init__(self, grant_uid: _Optional[str] = ..., epoch: _Optional[int] = ..., seq: _Optional[int] = ...) -> None: ...

class FiberLimits(_message.Message):
    __slots__ = ["max", "warm"]
    MAX_FIELD_NUMBER: _ClassVar[int]
    WARM_FIELD_NUMBER: _ClassVar[int]
    max: int
    warm: int
    def __init__(self, max: _Optional[int] = ..., warm: _Optional[int] = ...) -> None: ...

class Miss(_message.Message):
    __slots__ = ["code", "issuer", "preferred_home", "retry_after_s"]
    CODE_FIELD_NUMBER: _ClassVar[int]
    ISSUER_FIELD_NUMBER: _ClassVar[int]
    PREFERRED_HOME_FIELD_NUMBER: _ClassVar[int]
    RETRY_AFTER_S_FIELD_NUMBER: _ClassVar[int]
    code: MissCode
    issuer: str
    preferred_home: str
    retry_after_s: int
    def __init__(self, code: _Optional[_Union[MissCode, str]] = ..., retry_after_s: _Optional[int] = ..., issuer: _Optional[str] = ..., preferred_home: _Optional[str] = ...) -> None: ...

class ParkRequest(_message.Message):
    __slots__ = ["fiber_id", "sync"]
    FIBER_ID_FIELD_NUMBER: _ClassVar[int]
    SYNC_FIELD_NUMBER: _ClassVar[int]
    fiber_id: str
    sync: bool
    def __init__(self, fiber_id: _Optional[str] = ..., sync: bool = ...) -> None: ...

class Policy(_message.Message):
    __slots__ = ["audit_class", "durability", "endpoint_mode", "isolation", "psi_some_avg10_park", "psi_some_avg10_shed", "session_class"]
    AUDIT_CLASS_FIELD_NUMBER: _ClassVar[int]
    DURABILITY_FIELD_NUMBER: _ClassVar[int]
    ENDPOINT_MODE_FIELD_NUMBER: _ClassVar[int]
    ISOLATION_FIELD_NUMBER: _ClassVar[int]
    PSI_SOME_AVG10_PARK_FIELD_NUMBER: _ClassVar[int]
    PSI_SOME_AVG10_SHED_FIELD_NUMBER: _ClassVar[int]
    SESSION_CLASS_FIELD_NUMBER: _ClassVar[int]
    audit_class: str
    durability: Durability
    endpoint_mode: EndpointMode
    isolation: Isolation
    psi_some_avg10_park: float
    psi_some_avg10_shed: float
    session_class: str
    def __init__(self, durability: _Optional[_Union[Durability, str]] = ..., session_class: _Optional[str] = ..., audit_class: _Optional[str] = ..., psi_some_avg10_shed: _Optional[float] = ..., psi_some_avg10_park: _Optional[float] = ..., isolation: _Optional[_Union[Isolation, str]] = ..., endpoint_mode: _Optional[_Union[EndpointMode, str]] = ...) -> None: ...

class ReleaseRequest(_message.Message):
    __slots__ = ["discard", "fiber_id"]
    DISCARD_FIELD_NUMBER: _ClassVar[int]
    FIBER_ID_FIELD_NUMBER: _ClassVar[int]
    discard: bool
    fiber_id: str
    def __init__(self, fiber_id: _Optional[str] = ..., discard: bool = ...) -> None: ...

class Status(_message.Message):
    __slots__ = ["grant_uid", "latest", "parked", "pooled", "running", "w_used_bytes"]
    GRANT_UID_FIELD_NUMBER: _ClassVar[int]
    LATEST_FIELD_NUMBER: _ClassVar[int]
    PARKED_FIELD_NUMBER: _ClassVar[int]
    POOLED_FIELD_NUMBER: _ClassVar[int]
    RUNNING_FIELD_NUMBER: _ClassVar[int]
    W_USED_BYTES_FIELD_NUMBER: _ClassVar[int]
    grant_uid: str
    latest: Fence
    parked: int
    pooled: int
    running: int
    w_used_bytes: int
    def __init__(self, grant_uid: _Optional[str] = ..., running: _Optional[int] = ..., parked: _Optional[int] = ..., w_used_bytes: _Optional[int] = ..., latest: _Optional[_Union[Fence, _Mapping]] = ..., pooled: _Optional[int] = ...) -> None: ...

class Tier(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Durability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Isolation(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class EndpointMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class CloneKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class MissCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

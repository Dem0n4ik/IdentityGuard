from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class NormalizedEvent(_message.Message):
    __slots__ = ("event_id", "account_id", "identity_id", "occurred_ms", "event_name", "event_source", "event_category", "aws_region")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    ACCOUNT_ID_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_ID_FIELD_NUMBER: _ClassVar[int]
    OCCURRED_MS_FIELD_NUMBER: _ClassVar[int]
    EVENT_NAME_FIELD_NUMBER: _ClassVar[int]
    EVENT_SOURCE_FIELD_NUMBER: _ClassVar[int]
    EVENT_CATEGORY_FIELD_NUMBER: _ClassVar[int]
    AWS_REGION_FIELD_NUMBER: _ClassVar[int]
    event_id: str
    account_id: str
    identity_id: str
    occurred_ms: int
    event_name: str
    event_source: str
    event_category: str
    aws_region: str
    def __init__(self, event_id: _Optional[str] = ..., account_id: _Optional[str] = ..., identity_id: _Optional[str] = ..., occurred_ms: _Optional[int] = ..., event_name: _Optional[str] = ..., event_source: _Optional[str] = ..., event_category: _Optional[str] = ..., aws_region: _Optional[str] = ...) -> None: ...

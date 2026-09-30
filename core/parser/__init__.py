"""Email MIME parser – proper header, body, and attachment extraction.

Public API
----------
.. autofunction:: parse_eml_file
.. autofunction:: parse_eml_bytes

Data models
-----------
.. autoclass:: ParsedEmail
.. autoclass:: HeaderInfo
.. autoclass:: ReceivedHop
.. autoclass:: AuthResults
.. autoclass:: AttachmentInfo
.. autoclass:: FileHashes
"""
from .eml_parser import parse_eml_file, parse_eml_bytes
from .models import (
    AttachmentInfo,
    AuthResults,
    FileHashes,
    HeaderInfo,
    ParsedEmail,
    ReceivedHop,
)

__all__ = [
    "parse_eml_file",
    "parse_eml_bytes",
    "ParsedEmail",
    "HeaderInfo",
    "ReceivedHop",
    "AuthResults",
    "AttachmentInfo",
    "FileHashes",
]

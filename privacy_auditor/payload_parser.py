import re
import json
from urllib.parse import parse_qs, unquote, urlparse
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .traffic_capture import PacketRecord


class PayloadType(Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    JSON = "json"
    FORM_URLENCODED = "form_urlencoded"
    TELEMETRY = "telemetry"
    PLAINTEXT = "plaintext"
    BINARY = "binary"
    UNKNOWN = "unknown"


@dataclass
class HTTPRequestData:
    method: str = ""
    path: str = ""
    http_version: str = ""
    host: str = ""
    user_agent: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    body: str = ""
    body_parsed: Optional[Dict[str, Any]] = None
    content_type: str = ""


@dataclass
class ParsedPayload:
    payload_type: PayloadType
    raw_text: str
    http_request: Optional[HTTPRequestData] = None
    json_data: Optional[Dict[str, Any]] = None
    form_data: Optional[Dict[str, Any]] = None
    plaintext: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def extract_all_key_values(self) -> Dict[str, Any]:
        result = {}
        if self.http_request:
            result.update(self.http_request.query_params)
            result.update(self.http_request.headers)
            if self.http_request.body_parsed:
                result.update(self.http_request.body_parsed)
        if self.json_data:
            result.update(self.json_data)
        if self.form_data:
            result.update(self.form_data)
        return result


class PayloadParser:
    HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'}

    @staticmethod
    def _decode_payload(payload: bytes) -> str:
        for encoding in ['utf-8', 'gbk', 'latin-1', 'ascii']:
            try:
                return payload.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return payload.decode('utf-8', errors='replace')

    @staticmethod
    def _looks_like_binary(text: str) -> bool:
        if len(text) == 0:
            return False
        non_printable = sum(1 for c in text if ord(c) < 32 and c not in '\r\n\t')
        return (non_printable / len(text)) > 0.3

    @staticmethod
    def _parse_headers(header_lines: List[str]) -> Dict[str, str]:
        headers = {}
        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    @classmethod
    def parse_http_request(cls, text: str) -> Optional[HTTPRequestData]:
        lines = text.split('\r\n')
        if not lines:
            return None

        request_line = lines[0].strip()
        method_match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d\.\d)$', request_line)
        if not method_match:
            return None

        req = HTTPRequestData()
        req.method, req.path, req.http_version = method_match.groups()

        header_end = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                header_end = i
                break
        else:
            header_end = len(lines)

        req.headers = cls._parse_headers(lines[1:header_end])
        req.host = req.headers.get('Host', '')
        req.user_agent = req.headers.get('User-Agent', '')
        req.content_type = req.headers.get('Content-Type', '')

        parsed_url = urlparse(req.path)
        if parsed_url.query:
            try:
                qs = parse_qs(parsed_url.query, keep_blank_values=True)
                req.query_params = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
            except Exception:
                pass

        if header_end < len(lines):
            body_lines = lines[header_end + 1:]
            req.body = '\r\n'.join(body_lines)

            if 'application/json' in req.content_type.lower() and req.body.strip():
                try:
                    req.body_parsed = json.loads(req.body)
                except (json.JSONDecodeError, ValueError):
                    pass
            elif 'application/x-www-form-urlencoded' in req.content_type.lower() and req.body.strip():
                try:
                    qs = parse_qs(req.body, keep_blank_values=True)
                    req.body_parsed = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
                except Exception:
                    pass
            elif req.body.strip():
                try:
                    req.body_parsed = json.loads(req.body)
                except Exception:
                    pass

        return req

    @staticmethod
    def parse_http_response(text: str) -> bool:
        lines = text.split('\r\n')
        if not lines:
            return False
        return bool(re.match(r'^HTTP/\d\.\d\s+\d{3}\s+', lines[0].strip()))

    @staticmethod
    def parse_json(text: str) -> Optional[Dict[str, Any]]:
        stripped = text.strip()
        if not stripped:
            return None
        try:
            if stripped.startswith('{') or stripped.startswith('['):
                data = json.loads(stripped)
                if isinstance(data, dict):
                    return data
                elif isinstance(data, list):
                    return {"_array_data": data}
        except (json.JSONDecodeError, ValueError):
            pass
        return None

    @staticmethod
    def parse_form_urlencoded(text: str) -> Optional[Dict[str, Any]]:
        stripped = text.strip()
        if not stripped:
            return None
        if re.match(r'^[\w\-\.]+(=[^&]*)?(&[\w\-\.]+(=[^&]*)?)*$', stripped):
            try:
                qs = parse_qs(stripped, keep_blank_values=True)
                result = {}
                for k, v in qs.items():
                    key = unquote(k)
                    val = [unquote(x) for x in v]
                    result[key] = val[0] if len(val) == 1 else val
                if result:
                    return result
            except Exception:
                pass
        return None

    @staticmethod
    def _is_telemetry_pattern(payload_type: PayloadType, data: Dict[str, Any], raw_text: str) -> bool:
        telemetry_keywords = {
            'telemetry', 'metrics', 'track', 'event', 'analytics', 'ping', 'heartbeat',
            'report', 'diagnostic', 'usage', 'stat', 'device_id', 'machine_id',
            'install_id', 'session_id', 'user_id', 'uuid', 'mac', 'uptime',
            'app_version', 'os_version', 'crash', 'log', 'sentry', 'datadog'
        }
        for key in data.keys():
            if any(kw in key.lower() for kw in telemetry_keywords):
                return True
        if any(kw in raw_text.lower() for kw in telemetry_keywords):
            return True
        return False

    @classmethod
    def parse(cls, packet: PacketRecord) -> ParsedPayload:
        raw_text = cls._decode_payload(packet.payload)

        if not raw_text.strip() or cls._looks_like_binary(raw_text):
            return ParsedPayload(
                payload_type=PayloadType.BINARY,
                raw_text=raw_text[:512] if raw_text else ""
            )

        http_req = cls.parse_http_request(raw_text)
        if http_req:
            parsed = ParsedPayload(
                payload_type=PayloadType.HTTP_REQUEST,
                raw_text=raw_text,
                http_request=http_req
            )
            kvs = parsed.extract_all_key_values()
            if cls._is_telemetry_pattern(PayloadType.HTTP_REQUEST, kvs, raw_text):
                parsed.payload_type = PayloadType.TELEMETRY
                parsed.metadata['telemetry_hint'] = 'http_telemetry'
            return parsed

        if cls.parse_http_response(raw_text):
            return ParsedPayload(
                payload_type=PayloadType.HTTP_RESPONSE,
                raw_text=raw_text
            )

        json_data = cls.parse_json(raw_text)
        if json_data:
            parsed = ParsedPayload(
                payload_type=PayloadType.JSON,
                raw_text=raw_text,
                json_data=json_data
            )
            if cls._is_telemetry_pattern(PayloadType.JSON, json_data, raw_text):
                parsed.payload_type = PayloadType.TELEMETRY
                parsed.metadata['telemetry_hint'] = 'json_telemetry'
            return parsed

        form_data = cls.parse_form_urlencoded(raw_text)
        if form_data:
            parsed = ParsedPayload(
                payload_type=PayloadType.FORM_URLENCODED,
                raw_text=raw_text,
                form_data=form_data
            )
            if cls._is_telemetry_pattern(PayloadType.FORM_URLENCODED, form_data, raw_text):
                parsed.payload_type = PayloadType.TELEMETRY
                parsed.metadata['telemetry_hint'] = 'form_telemetry'
            return parsed

        return ParsedPayload(
            payload_type=PayloadType.PLAINTEXT,
            raw_text=raw_text,
            plaintext=raw_text
        )

    @classmethod
    def parse_many(cls, packets: List[PacketRecord]) -> List[Tuple[PacketRecord, ParsedPayload]]:
        results = []
        for pkt in packets:
            if pkt.payload and len(pkt.payload) > 0:
                parsed = cls.parse(pkt)
                if parsed.payload_type != PayloadType.BINARY:
                    results.append((pkt, parsed))
        return results

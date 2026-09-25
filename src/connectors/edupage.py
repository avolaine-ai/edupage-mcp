"""Small, unofficial EduPage HTTP connector. No writes to school workflows.

Authentication is explicit; no automatic password retries, persisted cookies or
logging. A client belongs to exactly one school/account and is not thread-safe.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import zlib
from dataclasses import dataclass, field
from datetime import date
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlsplit

import requests


class ConnectorError(Exception):
    """Only fixed error codes cross the connector boundary, never HTTP bodies."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Attachment:
    reference: str
    name: str = field(repr=False)


@dataclass(frozen=True)
class Message:
    source_id: str
    kind: str
    timestamp: str
    text: str = field(repr=False)
    data: dict = field(repr=False)
    recipient_ref: str = field(repr=False)
    content_hash: str
    attachments: tuple[Attachment, ...] = ()
    removed: bool = False
    child_candidates: tuple[str, ...] = ()


class _Inputs(HTMLParser):
    def __init__(self, html: str):
        super().__init__()
        self.fields = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'input' and attrs.get('name'):
            self.fields[attrs['name']] = attrs.get('value', '')


def _rpc_body(params: dict) -> dict:
    raw = urlencode({'rpcparams': json.dumps(params, ensure_ascii=True)}).encode()
    compressor = zlib.compressobj(wbits=-15)
    encoded = base64.b64encode(compressor.compress(raw) + compressor.flush()).decode()
    return {'eqap': 'dz:' + encoded, 'eqacs': hashlib.sha1(encoded.encode()).hexdigest(), 'eqaz': '1'}


def _json(payload: bytes) -> dict:
    try:
        if payload.startswith((b'eqz:', b'eqwd:')):
            payload = base64.b64decode(payload.split(b':', 1)[1], validate=True)
        obj = json.loads(payload)
        if not isinstance(obj, dict):
            raise ValueError()
        return obj
    except (ValueError, UnicodeError):
        raise ConnectorError('SCHEMA_CHANGED') from None


class EduPageClient:
    def __init__(self, school: str, *, session=None, download_hosts=()):
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', school) or school == 'login1':
            raise ConnectorError('SCHOOL_REQUIRED')
        self.host = school + '.edupage.org'
        self.base = 'https://' + self.host
        self._session = session or requests.Session()
        # No ambient proxy/netrc credentials; each connector owns its authentication.
        self._session.trust_env = False
        self._auth_hosts = {self.host, 'login1.edupage.org'}
        self._download_hosts = {self.host, *download_hosts}
        if any(not re.fullmatch(r'[a-z0-9.-]+\.edupage\.org', h) for h in self._download_hosts):
            raise ConnectorError('UNSAFE_HOST')
        self.state = 'AUTH_REQUIRED'
        self._challenge = None
        self._account_scope = None
        self._attachments = {}
        self._child_groups: dict[str, set[str]] = {}
        self.coverage: dict = {}

    @property
    def child_count(self) -> int:
        """Return the number of children confirmed by the current parent profile."""
        return len(self._child_groups)

    def _read_child_groups(self, identity: dict) -> None:
        """Keep only groups belonging to children listed in this parent account."""
        self._child_groups.clear()
        children = identity.get('parentStudentids')
        groups = identity.get('childGroups')
        if not isinstance(children, list) or not isinstance(groups, dict):
            return
        if any(not isinstance(child, (str, int)) for child in children):
            return
        allowed = {str(child) for child in children}
        if set(groups) != allowed:
            return
        if any(not isinstance(values, list) or any(not isinstance(v, str) for v in values)
               for values in groups.values()):
            return
        for child, values in groups.items():
            expanded = set(values)
            expanded.add('StudRodic' + child)
            userid = identity['userid']
            if isinstance(userid, str) and userid.startswith('Rodic'):
                expanded.add(userid.replace('Rodic', 'RStud', 1) + '@' + child)
            for group in values:
                if re.search(r'Trieda[0-9-]+$', group):
                    expanded.add(group.replace('Trieda', 'Rodicko', 1))
                if re.fullmatch(r'Plan[0-9-]+', group):
                    expanded.add('Rodic' + group)
            self._child_groups[child] = expanded

    def _child_candidates(self, recipient: str) -> tuple[str, ...]:
        """Return scoped candidate references, never a verified semantic assignment."""
        return tuple(sorted(hashlib.sha256((self._account_scope + '\0child\0' + child).encode()).hexdigest()
                            for child, groups in self._child_groups.items() if recipient in groups))

    def close(self):
        self._challenge = None
        self._attachments.clear()
        self._child_groups.clear()
        self.coverage.clear()
        self._session.cookies.clear()
        self._session.close()
        self.state = 'AUTH_REQUIRED'

    def _request(self, method, path, *, data=None, download=False, limit=5_000_000):
        url = urljoin(self.base, path)
        hosts = self._download_hosts if download else self._auth_hosts
        try:
            for _ in range(6):
                parsed = urlsplit(url)
                if (parsed.scheme != 'https' or parsed.hostname not in hosts
                        or parsed.port not in (None, 443) or parsed.username or parsed.password):
                    raise ConnectorError('UNSAFE_REDIRECT')
                with self._session.request(method, url, data=data, timeout=(10, 25),
                                           allow_redirects=False, stream=True) as response:
                    status = response.status_code
                    if status in (301, 302, 303, 307, 308):
                        target = urljoin(url, response.headers.get('Location', ''))
                        if not response.headers.get('Location'):
                            raise ConnectorError('SCHEMA_CHANGED')
                        if method != 'GET':
                            if status in (307, 308):
                                raise ConnectorError('UNSAFE_REDIRECT')
                            method, data = 'GET', None
                        url = target
                        continue
                    if status in (401, 403):
                        self.state = 'AUTH_REQUIRED'
                        raise ConnectorError('AUTH_REQUIRED')
                    if status == 429:
                        raise ConnectorError('RATE_LIMITED')
                    if status >= 500:
                        raise ConnectorError('TEMPORARY_ERROR')
                    if status != 200:
                        raise ConnectorError('HTTP_ERROR')
                    chunks, size = [], 0
                    for chunk in response.iter_content(65536):
                        size += len(chunk)
                        if size > limit:
                            raise ConnectorError('RESPONSE_TOO_LARGE')
                        chunks.append(chunk)
                    return url, b''.join(chunks)
            raise ConnectorError('REDIRECT_LIMIT')
        except requests.RequestException:
            raise ConnectorError('TEMPORARY_ERROR') from None
        except ValueError:
            raise ConnectorError('UNSAFE_REDIRECT') from None

    def _rpc(self, action, params):
        _, raw = self._request('POST', '/login/?cmd=MainLogin&akcia=' + action, data=_rpc_body(params))
        return _json(raw)

    def login(self, username: str, password: str) -> str:
        self._session.cookies.clear()
        self._challenge = None
        self._attachments.clear()
        self.state = 'AUTH_REQUIRED'
        self._account_scope = hashlib.sha256((self.host + '\0' + username).encode()).hexdigest()
        self._request('GET', '/login/?cmd=MainLogin')
        token = self._rpc('getToken', {'username': username, 'edupage': ''})
        if not isinstance(token.get('token'), str) or not token['token']:
            raise ConnectorError('LOGIN_REJECTED')
        result = self._rpc('login', {'username': username, 'password': password,
                          'userToken': token['token'], 'edupage': '', 'ctxt': '',
                          'tu': None, 'gu': None, 'au': None})
        if result.get('needCaptcha'):
            raise ConnectorError('CAPTCHA_REQUIRED')
        if not isinstance(result.get('redirectUrl'), str):
            raise ConnectorError('LOGIN_REJECTED')
        target, raw = self._request('GET', result['redirectUrl'])
        if 'twofactor' in urlsplit(target).path:
            self._load_challenge(raw)
            return self.state
        self.check_auth()
        return self.state

    def restore_browser_session(self, username: str, cookies: list[dict]) -> dict:
        """Restore scoped browser cookies and verify the authenticated resource.

        Args:
            username: Local account label used for source identity.
            cookies: Playwright cookie records, kept out of logs and files.

        Returns:
            Authenticated user metadata for checking the saved account identity.

        Raises:
            ConnectorError: If cookies are malformed, out of scope or expired.
        """
        self.state = 'AUTH_REQUIRED'
        self._session.cookies.clear()
        self._attachments.clear()
        self._challenge = None
        allowed = {self.host, '.' + self.host, 'edupage.org', '.edupage.org'}
        if not username or not isinstance(cookies, list) or not 0 < len(cookies) <= 100:
            raise ConnectorError('INVALID_SESSION')
        validated = []
        for cookie in cookies:
            if (not isinstance(cookie, dict) or cookie.get('domain') not in allowed
                    or not isinstance(cookie.get('name'), str) or not cookie['name']
                    or not isinstance(cookie.get('value'), str)
                    or not isinstance(cookie.get('path'), str) or not cookie['path'].startswith('/')
                    or not isinstance(cookie.get('expires', -1), (int, float))
                    or any(c in cookie['name'] + cookie['value'] for c in '\r\n;')):
                raise ConnectorError('INVALID_SESSION')
            expiry = cookie.get('expires', -1)
            if expiry > 0 and expiry <= time.time():
                continue
            validated.append(cookie)
        if not validated:
            raise ConnectorError('AUTH_REQUIRED')
        for cookie in validated:
            self._session.cookies.set(cookie['name'], cookie['value'],
                domain=cookie['domain'], path=cookie['path'], secure=True)
        self._account_scope = hashlib.sha256((self.host + '\0' + username).encode()).hexdigest()
        return self.check_auth()

    def _load_challenge(self, raw):
        text = raw.decode('utf-8', errors='replace')
        match = re.search(r'\bvar\s+props\s*=\s*', text)
        if match:
            try:
                props, _ = json.JSONDecoder().raw_decode(text[match.end():])
                if isinstance(props, dict) and props.get('requestid') and 'au' in props and 'gu' in props:
                    self._challenge = {k: props.get(k) or None for k in ('tu', 'gu', 'au')}
                    self.state = 'MFA_REQUIRED'
                    return
            except ValueError:
                pass
        fields = _Inputs(text).fields
        required = ('csrfauth', 'au', 'gu')
        if not all(fields.get(k) for k in required):
            raise ConnectorError('SCHEMA_CHANGED')
        self._challenge = {k: fields[k] for k in required}
        self.state = 'MFA_REQUIRED'

    def request_email_code(self):
        if self.state != 'MFA_REQUIRED':
            raise ConnectorError('MFA_NOT_PENDING')
        _, raw = self._request('POST', '/login/twofactor?akcia=sendEmail', data={})
        result = _json(raw)
        if result.get('status') != 'ok':
            details = result.get('data')
            if isinstance(details, dict) and details.get('retryInSeconds'):
                raise ConnectorError('RATE_LIMITED')
            raise ConnectorError('MFA_EMAIL_FAILED')

    def submit_code(self, code: str):
        if self.state != 'MFA_REQUIRED' or not self._challenge:
            raise ConnectorError('MFA_NOT_PENDING')
        if not re.fullmatch(r'[A-Za-z0-9 -]{4,32}', code):
            raise ConnectorError('INVALID_CODE_FORMAT')
        params = {**self._challenge, 't2fasec': code.strip(), '2fNoSave': 'y', '2fform': '1'}
        if 'csrfauth' in self._challenge:
            self._request('POST', '/login/edubarLogin.php', data=params)
        else:
            result = self._rpc('login', params)
            if result.get('status') != 'OK':
                raise ConnectorError('MFA_REJECTED')
            if isinstance(result.get('redirectUrl'), str):
                self._request('GET', result['redirectUrl'])
        # Verify the actual authenticated resource, never just a 200 response.
        self.check_auth()
        self._challenge = None
        return self.state

    def check_auth(self):
        self._child_groups.clear()
        url, raw = self._request('GET', '/user/')
        if '/login' in urlsplit(url).path:
            self.state = 'AUTH_REQUIRED'
            raise ConnectorError('AUTH_REQUIRED')
        text = raw.decode('utf-8', errors='replace')
        match = re.search(r'\buserhome\s*\(', text)
        try:
            data, _ = json.JSONDecoder().raw_decode(text[match.end():].lstrip()) if match else (None, 0)
            if not isinstance(data, dict) or not data.get('userid'):
                raise ValueError()
        except (ValueError, TypeError):
            self.state = 'UNKNOWN'
            raise ConnectorError('SCHEMA_CHANGED') from None
        self.state = 'READY'
        self._read_child_groups(data)
        return data

    def list_messages(self, since: date) -> list[Message]:
        self.coverage.clear()
        if self.state != 'READY':
            raise ConnectorError('AUTH_REQUIRED')
        url, raw = self._request('POST', '/timeline/?' + urlencode([
            ('module', 'todo'), ('filterTab', ''), ('akcia', 'getData'), ('filterTab', 'messages')]),
            data={'datefrom': since.isoformat()})
        if '/login' in urlsplit(url).path:
            self.state = 'AUTH_REQUIRED'
            raise ConnectorError('AUTH_REQUIRED')
        data = _json(raw)
        if not isinstance(data.get('timelineItems'), list):
            raise ConnectorError('SCHEMA_CHANGED')
        messages = {}
        attachment_urls = {}
        for row in data['timelineItems']:
            if not isinstance(row, dict) or not row.get('timelineid') or not isinstance(row.get('text'), str):
                raise ConnectorError('SCHEMA_CHANGED')
            extra = row.get('data', {})
            # The live timeline also uses JSON null for absent optional metadata.
            # Keep the message; do not discard a complete batch for this case.
            if extra is None or (isinstance(extra, str) and extra.strip() == 'null'):
                extra = {}
            if isinstance(extra, str):
                extra = _json(extra.encode())
            if not isinstance(extra, dict):
                raise ConnectorError('SCHEMA_CHANGED')
            source_id = self._account_scope + ':' + str(row['timelineid'])
            canonical = {'text': row['text'], 'data': extra, 'recipient': row.get('user', ''),
                         'timestamp': row.get('timestamp', ''), 'kind': row.get('typ', ''),
                         'removed': row.get('removed') in (True, 1, '1')}
            digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            if extra.get('attachments'):
                raise ConnectorError('UNSUPPORTED_ATTACHMENT_SCHEMA')
            links = extra.get('attachements') or {}
            if not isinstance(links, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in links.items()):
                raise ConnectorError('UNSUPPORTED_ATTACHMENT_SCHEMA')
            attachments = []
            for link, name in links.items():
                ref = hashlib.sha256((source_id + '\0' + link).encode()).hexdigest()
                attachment_urls[ref] = urljoin(self.base, link)
                attachments.append(Attachment(ref, name))
            message = Message(source_id, canonical['kind'], canonical['timestamp'],
                              row['text'], extra, str(canonical['recipient']), digest,
                              tuple(attachments), canonical['removed'],
                              self._child_candidates(str(canonical['recipient'])))
            if source_id in messages and messages[source_id].content_hash != digest:
                raise ConnectorError('CONFLICTING_DUPLICATE')
            messages[source_id] = message
        # Publish references only after the complete batch passed validation.
        self._attachments = attachment_urls
        self.coverage = {'requested_since': since.isoformat(), 'complete_archive': False,
                         'child_count': self.child_count, 'child_mapping_verified': False}
        for key in ('datefrom', 'dateto', 'mindate', 'maxdate'):
            value = data.get(key)
            if isinstance(value, str):
                try:
                    self.coverage['reported_' + key] = date.fromisoformat(value).isoformat()
                except ValueError:
                    pass
        return list(messages.values())

    def download_pdf(self, attachment: Attachment) -> bytes:
        if self.state != 'READY':
            raise ConnectorError('AUTH_REQUIRED')
        url = self._attachments.get(attachment.reference)
        if not url:
            raise ConnectorError('UNKNOWN_ATTACHMENT')
        parsed = urlsplit(url)
        if parsed.hostname != self.host or parsed.path != '/elearning/ruqjzfpv':
            raise ConnectorError('UNSUPPORTED_ATTACHMENT_URL')
        target, raw = self._request('GET', url, download=True, limit=20_000_000)
        if '/login' in urlsplit(target).path:
            self.state = 'AUTH_REQUIRED'
            raise ConnectorError('AUTH_REQUIRED')
        if not raw.startswith(b'%PDF-'):
            raise ConnectorError('NOT_A_PDF')
        return raw

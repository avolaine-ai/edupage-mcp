"""Offline tests for session boundaries and account-bound MCP tools."""
from __future__ import annotations

import asyncio
from datetime import date, timedelta
import json
from pathlib import Path
import sys
from unittest.mock import MagicMock

import pytest
import keyring

from src.connectors.edupage import Attachment, ConnectorError, EduPageClient, Message
from src.edupage_mcp import EduPageTools, create_server, save_browser_session, session_key


def cookie(**changes: object) -> dict:
    """Make a synthetic browser cookie with no real account data."""
    return {'name': 'session', 'value': 'synthetic-only', 'domain': 'test.edupage.org',
            'path': '/', 'expires': -1, **changes}


@pytest.mark.parametrize('changes', [
    {'domain': 'evil.invalid'}, {'domain': 'other.edupage.org'},
    {'path': 'invalid'}, {'value': 'bad\r\nheader'}, {'name': ''}, {'expires': 'tomorrow'},
])
def test_restore_rejects_cookie_before_network(changes: dict) -> None:
    """Out-of-scope and malformed browser state cannot reach the network."""
    session = MagicMock()
    client = EduPageClient('test', session=session)
    with pytest.raises(ConnectorError, match='INVALID_SESSION'):
        client.restore_browser_session('local-account', [cookie(**changes)])
    session.request.assert_not_called()
    session.cookies.set.assert_not_called()


def test_expired_cookie_cannot_authenticate() -> None:
    """Expired saved cookies demand a fresh login."""
    client = EduPageClient('test', session=MagicMock())
    with pytest.raises(ConnectorError, match='AUTH_REQUIRED'):
        client.restore_browser_session('account', [cookie(expires=1)])


def test_restore_verifies_user_and_scopes_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restored sessions must pass the same user endpoint verification as login."""
    client = EduPageClient('test', session=MagicMock())
    check = MagicMock(return_value={'userid': 'fixture-user'})
    monkeypatch.setattr(client, 'check_auth', check)
    assert client.restore_browser_session('account', [cookie()]) == {'userid': 'fixture-user'}
    check.assert_called_once()
    assert client._account_scope
    assert client._session.cookies.set.call_args.kwargs['secure'] is True


def test_keychain_is_only_written_after_verified_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """A login page or failed auth must not replace a saved working session."""
    client = MagicMock()
    client.restore_browser_session.side_effect = ConnectorError('AUTH_REQUIRED')
    monkeypatch.setattr('src.edupage_mcp.EduPageClient', lambda *a, **k: client)
    write = MagicMock()
    monkeypatch.setattr('src.edupage_mcp.keyring.set_password', write)
    with pytest.raises(ConnectorError):
        save_browser_session('test', 'account', [cookie()])
    write.assert_not_called()
    client.close.assert_called_once()


def test_saved_session_is_account_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sessions for different school/account combinations use distinct entries."""
    client = MagicMock()
    client.restore_browser_session.return_value = {'userid': 'verified-user'}
    monkeypatch.setattr('src.edupage_mcp.EduPageClient', lambda *a, **k: client)
    write = MagicMock()
    monkeypatch.setattr('src.edupage_mcp.keyring.set_password', write)
    assert save_browser_session('test', 'account', [cookie()])['status'] == 'READY'
    assert write.call_args.args[0] == 'family-operation-system'
    saved = json.loads(write.call_args.args[2])
    assert saved['userid'] == 'verified-user'
    assert session_key('test', 'a') != session_key('test', 'b')
    assert session_key('test', 'a') != session_key('other', 'a')


def test_keychain_write_error_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    """An import failure reports its boundary without exposing keychain details."""
    client = MagicMock()
    client.restore_browser_session.return_value = {'userid': 'verified-user'}
    monkeypatch.setattr('src.edupage_mcp.EduPageClient', lambda *a, **k: client)
    write = MagicMock(side_effect=keyring.errors.KeyringError('private details'))
    monkeypatch.setattr('src.edupage_mcp.keyring.set_password', write)
    with pytest.raises(ConnectorError, match='^KEYCHAIN_UNAVAILABLE$'):
        save_browser_session('test', 'account', [cookie()])
    client.close.assert_called_once()


def test_missing_session_never_attempts_password_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """Authentication remains a separate user-driven browser operation."""
    monkeypatch.setattr('src.edupage_mcp.keyring.get_password', lambda *a: None)
    tools = EduPageTools('test', 'account')
    assert tools.call('auth_status') == {'status': 'AUTH_REQUIRED'}


def test_denied_keychain_read_is_distinct_from_expired_login(monkeypatch: pytest.MonkeyPatch) -> None:
    """A keychain failure must not trigger another portal login or leak details."""
    read = MagicMock(side_effect=keyring.errors.KeyringError('private details'))
    backend = MagicMock()
    monkeypatch.setattr('src.edupage_mcp.keyring.get_password', read)
    monkeypatch.setattr('src.edupage_mcp.EduPageClient', backend)
    assert EduPageTools('test', 'account').call('auth_status') == {'status': 'KEYCHAIN_ACCESS_REQUIRED'}
    backend.assert_not_called()


@pytest.mark.parametrize('result', [0, -1])
def test_background_keychain_guard_fails_closed(monkeypatch: pytest.MonkeyPatch, result: int) -> None:
    """The background process must not continue if disabling UI fails."""
    from src.edupage_mcp import disable_keychain_dialogs

    library = MagicMock()
    setter = library.SecKeychainSetUserInteractionAllowed
    setter.return_value = result
    monkeypatch.setattr('src.edupage_mcp.sys.platform', 'darwin')
    monkeypatch.setattr('src.edupage_mcp.ctypes.CDLL', lambda path: library)
    if result:
        with pytest.raises(ConnectorError, match='^KEYCHAIN_INTERACTION_GUARD_FAILED$'):
            disable_keychain_dialogs()
    else:
        disable_keychain_dialogs()
    setter.assert_called_once_with(False)


def test_rejects_account_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A restored session must match the identity captured at import time."""
    raw = json.dumps({'school': 'test', 'userid': 'expected', 'cookies': [cookie()]})
    monkeypatch.setattr('src.edupage_mcp.keyring.get_password', lambda *a: raw)
    client = MagicMock()
    client.restore_browser_session.return_value = {'userid': 'different'}
    monkeypatch.setattr('src.edupage_mcp.EduPageClient', lambda *a, **k: client)
    assert EduPageTools('test', 'account').call('auth_status') == {'status': 'ACCOUNT_MISMATCH'}
    client.close.assert_called_once()


def populated_tools() -> tuple[EduPageTools, MagicMock]:
    """Make a fake backend with one message and one PDF reference."""
    backend = MagicMock()
    backend.list_messages.return_value = [Message('m1', 'message', '2026-09-24',
        'Untrusted fixture text', {}, 'raw-child', 'version', (Attachment('a1', 'test.pdf'),))]
    backend.download_pdf.return_value = b'%PDF-fixture'
    tools = EduPageTools('test', 'account')
    tools.client = backend
    return tools, backend


def test_list_minimizes_data_and_get_requires_known_refs() -> None:
    """Metadata listing is separate from explicit content retrieval."""
    tools, backend = populated_tools()
    listing = tools.call('list_messages', since=date.today().isoformat())
    assert listing['complete_archive'] is False
    assert 'text' not in listing['messages'][0]
    message = tools.call('get_message', message_id='m1')
    assert message['content_is_untrusted'] is True
    assert message['receipt_requested'] is False
    assert tools.call('get_message', message_id='foreign')['status'] == 'UNKNOWN_MESSAGE'
    assert tools.call('get_attachment', message_id='m1', reference='https://evil.invalid')['status'] == 'UNKNOWN_ATTACHMENT'
    backend.download_pdf.assert_not_called()
    assert tools.call('get_attachment', message_id='m1', reference='a1')['mime_type'] == 'application/pdf'


def test_expired_session_clears_previously_cached_content() -> None:
    """Cached messages are unavailable after auth has failed."""
    tools, backend = populated_tools()
    tools.call('list_messages', since=date.today().isoformat())
    backend.check_auth.side_effect = ConnectorError('AUTH_REQUIRED')
    assert tools.call('get_message', message_id='m1') == {'status': 'AUTH_REQUIRED'}
    assert not tools.messages
    assert tools.client is None


def test_invalid_dates_and_unknown_operations_do_not_connect() -> None:
    """Tool inputs cannot turn the connector into an unrestricted API client."""
    tools, backend = populated_tools()
    for since in ['not-a-date', (date.today() - timedelta(days=91)).isoformat(),
                  (date.today() + timedelta(days=1)).isoformat()]:
        assert tools.call('list_messages', since=since)['status'] == 'INVALID_DATE_WINDOW'
    assert tools.call('send_message')['status'] == 'UNKNOWN_OPERATION'
    backend.check_auth.assert_not_called()


def test_unexpected_exception_does_not_leak_content() -> None:
    """Transport exceptions cannot disclose cookies or private response bodies."""
    tools, backend = populated_tools()
    backend.check_auth.side_effect = RuntimeError('private cookie and message')
    assert tools.call('auth_status') == {'status': 'LOCAL_ERROR'}


def test_sdk_exposes_only_fixed_tools() -> None:
    """The actual SDK registers the expected contract without secret parameters."""
    pytest.importorskip('mcp')
    tools, _ = populated_tools()
    server = create_server(tools)
    definitions = asyncio.run(server.list_tools())
    assert {t.name for t in definitions} == {'auth_status', 'list_messages', 'get_message', 'get_attachment'}
    assert all(t.annotations.readOnlyHint for t in definitions)
    assert all(t.outputSchema is not None for t in definitions)
    for definition in definitions:
        assert not {'password', 'cookies', 'url', 'school', 'username'} & set(definition.inputSchema.get('properties', {}))
    result = asyncio.run(server.call_tool('auth_status', {}))
    assert isinstance(result, tuple)
    assert result[1] == {'status': 'READY', 'scope': 'LOCAL_SINGLE_ACCOUNT'}


def test_real_stdio_protocol_returns_structured_content() -> None:
    """Exercise the live probe's contract over stdio with synthetic data only."""
    pytest.importorskip('mcp')
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def exercise() -> None:
        code = ('from tests.test_edupage_mcp import populated_tools; '
                'from src.edupage_mcp import create_server; '
                'tools, backend = populated_tools(); create_server(tools).run(transport="stdio")')
        params = StdioServerParameters(command=sys.executable, args=['-c', code],
                                      cwd=str(Path(__file__).resolve().parents[1]))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for name, arguments in [
                    ('auth_status', {}),
                    ('list_messages', {'since': date.today().isoformat()}),
                    ('get_message', {'message_id': 'm1'}),
                    ('get_attachment', {'message_id': 'm1', 'reference': 'a1'}),
                ]:
                    result = await session.call_tool(name, arguments)
                    assert not result.isError
                    assert result.structuredContent['status'] == 'READY'

    asyncio.run(exercise())


@pytest.mark.parametrize('has_pdf', [True, False])
def test_live_probe_checks_later_attachments_and_reports_missing_pdf(has_pdf: bool) -> None:
    """A non-PDF first attachment must not hide a later PDF or imply acceptance."""
    pytest.importorskip('mcp')
    from contextlib import asynccontextmanager
    from types import SimpleNamespace
    from unittest.mock import patch
    from scripts.probes import edupage_mcp_probe as probe

    calls = []

    class Session:
        async def initialize(self) -> None:
            pass

        async def list_tools(self) -> SimpleNamespace:
            return SimpleNamespace(tools=[None] * 4)

        async def call_tool(self, name: str, arguments: dict) -> SimpleNamespace:
            calls.append((name, arguments))
            data = {'status': 'READY'}
            if name == 'list_messages':
                data['messages'] = [{'id': str(i), 'version': 'v1', 'attachment_count': 1}
                                    for i in range(2)]
            elif name == 'get_message':
                suffix = 'pdf' if has_pdf and arguments['message_id'] == '1' else 'docx'
                data['attachments'] = [{'name': 'fixture.' + suffix, 'reference': 'a1'}]
            elif name == 'get_attachment':
                data['bytes'] = 12
            return SimpleNamespace(isError=False, structuredContent=data)

    @asynccontextmanager
    async def transport(*args: object, **kwargs: object):
        yield (None, None)

    @asynccontextmanager
    async def session(*args: object, **kwargs: object):
        yield Session()

    with patch.object(probe, 'stdio_client', transport), patch.object(probe, 'ClientSession', session):
        report, digest = asyncio.run(probe.run_once('test', date.today().isoformat(), []))
    assert digest
    assert report['pdf'] == ('READY' if has_pdf else 'NOT_VERIFIED')
    assert ('get_message', {'message_id': '1'}) in calls
    assert any(name == 'get_attachment' for name, _ in calls) == has_pdf

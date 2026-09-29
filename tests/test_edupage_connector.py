"""Offline boundary tests: no secrets and no school requests."""
import base64
import json
import zlib
from datetime import date
from unittest.mock import MagicMock
from urllib.parse import parse_qs

import pytest
import requests

from src.connectors.edupage import Attachment, ConnectorError, EduPageClient, _rpc_body


def response(body=b'', status=200, headers=None):
    result = MagicMock()
    result.status_code = status
    result.headers = headers or {}
    result.iter_content.return_value = iter([body])
    result.__enter__.return_value = result
    return result


def make_client(*responses, ready=False):
    session = MagicMock()
    session.request.side_effect = responses
    client = EduPageClient('test-school', session=session)
    if ready:
        client.state = 'READY'
        client._account_scope = 'test-account'
        client._attachments['test-ref'] = client.base + '/elearning/ruqjzfpv?id=fixture'
    return client, session


def encoded(data):
    return json.dumps(data).encode()


def row(**changes):
    return {'timelineid': '123', 'typ': 'sprava', 'text': 'Test message',
            'timestamp': '2026-09-23 10:00:00', 'user': 'student-1', 'data': '{}', **changes}


def test_password_login_reaches_current_react_mfa_without_browser():
    challenge = b'<script>var props = {"requestid":"private-challenge","au":"","gu":null};</script>'
    client, session = make_client(response(), response(encoded({'token': 'private-token'})),
        response(encoded({'redirectUrl': '/login/twofactor'})), response(challenge))
    assert client.login('test@example.invalid', 'private-password') == 'MFA_REQUIRED'
    assert session.request.call_count == 4
    assert client._challenge == {'tu': None, 'gu': None, 'au': None}
    # Wire encoding round-trips the actual password, including non-ASCII characters.
    body = _rpc_body({'password': 'päss&=字'})
    decoded = zlib.decompress(base64.b64decode(body['eqap'][3:]), -15).decode()
    assert json.loads(parse_qs(decoded)['rpcparams'][0])['password'] == 'päss&=字'


def test_rejected_password_is_not_retried_or_reported_in_error():
    client, session = make_client(response(), response(encoded({'token': 'secret'})),
        response(encoded({'err': {'error_text': 'private-response'}, 'status': 'ERROR'})))
    with pytest.raises(ConnectorError, match='^LOGIN_REJECTED$'):
        client.login('private-user', 'private-password')
    assert session.request.call_count == 3
    assert client.state == 'AUTH_REQUIRED'


def test_email_send_rate_limit_does_not_retry():
    client, session = make_client(response(encoded({'status': 'fail', 'data': {'retryInSeconds': 60}})))
    client.state = 'MFA_REQUIRED'
    with pytest.raises(ConnectorError, match='^RATE_LIMITED$'):
        client.request_email_code()
    assert session.request.call_count == 1


def test_submit_code_requires_authenticated_resource_not_just_ok():
    client, session = make_client(response(encoded({'status': 'OK'})), response(b'<html>Unexpected</html>'))
    client.state = 'MFA_REQUIRED'
    client._challenge = {'au': None, 'gu': None, 'tu': None}
    with pytest.raises(ConnectorError, match='^SCHEMA_CHANGED$'):
        client.submit_code('123456')
    assert client.state != 'READY'


def test_successful_code_keeps_two_factor_enabled():
    client, session = make_client(response(encoded({'status': 'OK', 'redirectUrl': '/user/'})),
        response(), response(b'<script>userhome({"userid":"parent-1","items":[]});</script>'))
    client.state = 'MFA_REQUIRED'
    client._challenge = {'au': None, 'gu': None, 'tu': None}
    assert client.submit_code('123456') == 'READY'
    body = session.request.call_args_list[0].kwargs['data']
    decoded = zlib.decompress(base64.b64decode(body['eqap'][3:]), -15).decode()
    fields = json.loads(parse_qs(decoded)['rpcparams'][0])
    assert fields['2fNoSave'] == 'y'
    assert client._challenge is None


def test_rejected_code_keeps_mfa_pending_and_does_not_retry():
    client, session = make_client(response(encoded({'status': 'ERROR', 'err': {'error_text': 'private'}})))
    client.state = 'MFA_REQUIRED'
    client._challenge = {'au': None, 'gu': None, 'tu': None}
    with pytest.raises(ConnectorError, match='^MFA_REJECTED$'):
        client.submit_code('123456')
    assert client.state == 'MFA_REQUIRED'
    assert session.request.call_count == 1


@pytest.mark.parametrize('target', ['https://evil.invalid/path', 'http://test-school.edupage.org/user/',
    'https://test-school.edupage.org.evil.invalid/', 'https://test-school.edupage.org:444/',
    'https://test-school.edupage.org@evil.invalid/'])
def test_redirect_never_leaks_credentials_to_other_origins(target):
    client, session = make_client(response(status=302, headers={'Location': target}))
    with pytest.raises(ConnectorError, match='^UNSAFE_REDIRECT$'):
        client._request('POST', '/login/', data={'password': 'private-password'})
    assert session.request.call_count == 1


def test_no_replay_of_password_post_on_307():
    client, session = make_client(response(status=307, headers={'Location': '/new-login'}))
    with pytest.raises(ConnectorError, match='^UNSAFE_REDIRECT$'):
        client._request('POST', '/login/', data={'password': 'private-password'})
    assert session.request.call_count == 1


def test_expired_session_is_not_empty_inbox():
    client, _ = make_client(response(status=302, headers={'Location': '/login/'}),
                           response(b'<html>Login</html>'), ready=True)
    with pytest.raises(ConnectorError, match='^AUTH_REQUIRED$'):
        client.list_messages(date(2026, 9, 1))
    assert client.state == 'AUTH_REQUIRED'


@pytest.mark.parametrize('payload', [b'{}', b'<html>Unknown</html>', b'{"timelineItems":{}}',
    encoded({'timelineItems': [{'text': 'missing id'}]})])
def test_unknown_schema_is_not_empty_inbox(payload):
    client, _ = make_client(response(payload), ready=True)
    with pytest.raises(ConnectorError, match='^SCHEMA_CHANGED$'):
        client.list_messages(date(2026, 9, 1))


def test_duplicate_and_edit_have_stable_identity_but_different_version():
    client, _ = make_client(response(encoded({'timelineItems': [row(), row()]})),
        response(encoded({'timelineItems': [row(text='Changed')]})), ready=True)
    first = client.list_messages(date(2026, 9, 1))
    second = client.list_messages(date(2026, 9, 1))
    assert len(first) == 1
    assert first[0].source_id == second[0].source_id
    assert first[0].content_hash != second[0].content_hash
    assert 'Test message' not in repr(first[0])


def test_receipt_message_uses_timeline_body_instead_of_placeholder():
    placeholder = 'Wichtige Nachricht, öffnen Sie die Nachricht, um den Inhalt anzuzeigen.'
    data = json.dumps({'receipt': '1', 'messageContent': 'Synthetic body'})
    client, session = make_client(response(encoded({'timelineItems': [
        row(text=placeholder, data=data), row(timelineid='124')]})), ready=True)
    important, plain = client.list_messages(date(2026, 9, 1))
    assert important.text == 'Synthetic body'
    assert important.receipt_requested is True
    assert plain.text == 'Test message'
    assert plain.receipt_requested is False
    # Reading the body must not open the message or confirm it.
    assert session.request.call_count == 1


def test_conflicting_rows_are_not_silently_dropped():
    client, _ = make_client(response(encoded({'timelineItems': [row(), row(text='Different')]})), ready=True)
    with pytest.raises(ConnectorError, match='^CONFLICTING_DUPLICATE$'):
        client.list_messages(date(2026, 9, 1))


def test_pdf_checks_signature_and_size_instead_of_http_status():
    client, _ = make_client(response(b'<html>Login</html>'), ready=True)
    with pytest.raises(ConnectorError, match='^NOT_A_PDF$'):
        client.download_pdf(Attachment('test-ref', 'test.pdf'))
    client, _ = make_client(response(b'123456'))
    with pytest.raises(ConnectorError, match='^RESPONSE_TOO_LARGE$'):
        client._request('GET', '/user/', limit=5)


def test_pdf_redirect_to_unconfigured_cdn_stops_before_request():
    client, session = make_client(response(status=301, headers={'Location': 'https://cloud.edupage.org/file'}), ready=True)
    with pytest.raises(ConnectorError, match='^UNSAFE_REDIRECT$'):
        client.download_pdf(Attachment('test-ref', 'test.pdf'))
    assert session.request.call_count == 1


def test_transport_errors_do_not_include_sensitive_url_or_body():
    client, session = make_client(requests.ConnectionError('password=private&cookie=private'))
    with pytest.raises(ConnectorError, match='^TEMPORARY_ERROR$'):
        client._request('GET', '/user/')
    assert session.request.call_count == 1


def test_attachment_download_only_accepts_known_message_reference():
    client, session = make_client(ready=True)
    with pytest.raises(ConnectorError, match='^UNKNOWN_ATTACHMENT$'):
        client.download_pdf(Attachment('invented-ref', 'test.pdf'))
    client._attachments['unsafe'] = client.base + '/login/logout.php'
    with pytest.raises(ConnectorError, match='^UNSUPPORTED_ATTACHMENT_URL$'):
        client.download_pdf(Attachment('unsafe', 'test.pdf'))
    session.request.assert_not_called()


def test_message_pdf_reference_downloads_without_browser():
    extra = {'attachements': {'/elearning/ruqjzfpv?id=fixture': 'test.pdf'}}
    client, _ = make_client(response(encoded({'timelineItems': [row(data=json.dumps(extra))]})),
                           response(b'%PDF-1.4\nfixture'), ready=True)
    message = client.list_messages(date(2026, 9, 1))[0]
    assert len(message.attachments) == 1
    assert client.download_pdf(message.attachments[0]).startswith(b'%PDF-')


def test_removal_changes_version_not_identity():
    client, _ = make_client(response(encoded({'timelineItems': [row()]})),
                           response(encoded({'timelineItems': [row(removed='1')]})), ready=True)
    original = client.list_messages(date(2026, 9, 1))[0]
    removed = client.list_messages(date(2026, 9, 1))[0]
    assert original.source_id == removed.source_id
    assert original.content_hash != removed.content_hash
    assert removed.removed


def test_unknown_attachment_format_fails_instead_of_losing_documents():
    extra = {'attachments': [{'url': '/file', 'name': 'test.pdf'}]}
    client, _ = make_client(response(encoded({'timelineItems': [row(data=extra)]})), ready=True)
    with pytest.raises(ConnectorError, match='^UNSUPPORTED_ATTACHMENT_SCHEMA$'):
        client.list_messages(date(2026, 9, 1))


def test_bad_batch_does_not_publish_partial_attachment_references():
    extra = {'attachements': {'/elearning/ruqjzfpv?id=fixture': 'test.pdf'}}
    client, _ = make_client(response(encoded({'timelineItems': [row(data=extra), {'text': 'bad row'}]})), ready=True)
    previous = dict(client._attachments)
    with pytest.raises(ConnectorError, match='^SCHEMA_CHANGED$'):
        client.list_messages(date(2026, 9, 1))
    assert client._attachments == previous


@pytest.mark.parametrize('metadata', [None, 'null', ' null '])
def test_null_metadata_keeps_message_and_other_attachments(metadata: object) -> None:
    """Optional absent metadata must not lose a message or the rest of the batch."""
    extra = {'attachements': {'/elearning/ruqjzfpv?id=fixture': 'test.pdf'}}
    client, _ = make_client(response(encoded({'timelineItems': [
        row(data=metadata), row(timelineid='456', data=extra)]})), ready=True)
    messages = client.list_messages(date(2026, 9, 1))
    assert len(messages) == 2
    assert messages[0].text == 'Test message'
    assert messages[0].data == {}
    assert len(messages[1].attachments) == 1


@pytest.mark.parametrize('metadata', ['broken-json', '[]', 'false', '42'])
def test_other_unexpected_metadata_still_fails(metadata: str) -> None:
    """Supporting observed null metadata must not hide unrelated schema failures."""
    client, _ = make_client(response(encoded({'timelineItems': [row(data=metadata)]})), ready=True)
    with pytest.raises(ConnectorError, match='^SCHEMA_CHANGED$'):
        client.list_messages(date(2026, 9, 1))


def test_child_candidates_are_account_scoped_and_can_include_siblings() -> None:
    """Shared groups retain both children without claiming verified relevance."""
    client, _ = make_client(response(encoded({'timelineItems': [row(user='Trieda-shared')]})), ready=True)
    identity = {'userid': 'Rodic-parent', 'parentStudentids': [-1, -2],
                'childGroups': {'-1': ['Trieda-shared'], '-2': ['Trieda-shared']}}
    client._read_child_groups(identity)
    items = client.list_messages(date(2026, 9, 1))
    assert len(items[0].child_candidates) == 2
    assert client.coverage['child_count'] == 2
    assert client.coverage['child_mapping_verified'] is False
    original = items[0].child_candidates
    client._account_scope = 'other-account'
    assert set(original).isdisjoint(client._child_candidates('Trieda-shared'))
    assert client._child_candidates('*') == ()


def test_parent_group_expansion_matches_known_frontend_rules() -> None:
    """Class parent groups are candidates; unrelated account children are excluded."""
    client, _ = make_client(ready=True)
    client._read_child_groups({'userid': 'Rodic-1', 'parentStudentids': [-2],
                               'childGroups': {'-2': ['Trieda-3', 'Plan-4']}})
    expected = client._child_candidates('Trieda-3')
    assert len(expected) == 1
    for recipient in ['Rodicko-3', 'RodicPlan-4', 'StudRodic-2', 'RStud-1@-2']:
        assert client._child_candidates(recipient) == expected
    client._read_child_groups({'userid': 'Rodic-1', 'parentStudentids': [-2],
                               'childGroups': {'-999': ['Trieda-3']}})
    assert client.child_count == 0
    assert client._child_candidates('Trieda-3') == ()


def test_failed_auth_clears_previous_child_context() -> None:
    """A failed account check cannot leave old child candidates available."""
    client, _ = make_client(response(b'<html>unknown</html>'), ready=True)
    client._read_child_groups({'userid': 'Rodic-1', 'parentStudentids': [-2],
                               'childGroups': {'-2': ['Trieda-3']}})
    with pytest.raises(ConnectorError):
        client.check_auth()
    assert client.child_count == 0

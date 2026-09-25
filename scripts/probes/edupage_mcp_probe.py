"""Explicit live MCP acceptance: only counts and fixed states are printed.

Run with the separate MCP environment, never as part of the offline test suite.
The probe starts the actual stdio server twice to verify keychain restoration.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[2]


async def run_once(school: str, since: str, download_hosts: list[str]) -> tuple[dict, str]:
    """Call real MCP tools without exposing returned source text in the console.

    Args:
        school: Configured school subdomain.
        since: ISO start date within the tool's supported window.
        download_hosts: Explicitly allowed EduPage PDF download hosts.

    Returns:
        Aggregate test results and a digest for comparing restarts.
    """
    args = ['-m', 'src.edupage_mcp', '--school', school]
    for host in download_hosts:
        args.extend(['--download-host', host])
    params = StdioServerParameters(command=sys.executable, args=args, cwd=str(ROOT))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(minutes=5)) as session:
            await session.initialize()
            definitions = await session.list_tools()

            async def call(name: str, arguments: dict) -> dict:
                print(json.dumps({'stage': name, 'status': 'STARTED'}), flush=True)
                result = await session.call_tool(name, arguments)
                if result.isError or result.structuredContent is None:
                    raise RuntimeError('PROTOCOL_ERROR')
                return result.structuredContent

            auth = await call('auth_status', {})
            if auth.get('status') != 'READY':
                return {'auth': auth.get('status'), 'tools': len(definitions.tools)}, ''
            first = await call('list_messages', {'since': since})
            second = await call('list_messages', {'since': since})
            if first.get('status') != 'READY' or second.get('status') != 'READY':
                return {'auth': 'READY', 'first_listing': first.get('status'),
                        'second_listing': second.get('status')}, ''
            versions = lambda data: {m['id']: m['version'] for m in data['messages']}
            report = {'auth': 'READY', 'tools': len(definitions.tools),
                      'messages': len(second['messages']),
                      'same_ids_and_versions': versions(first) == versions(second),
                      'message_read': False, 'pdf': 'NOT_VERIFIED'}
            candidates = second['messages']
            # Search all attachment-bearing messages, not just the first one.
            selected = [m for m in candidates if m['attachment_count']] or candidates[:1]
            for chosen in selected:
                message = await call('get_message', {'message_id': chosen['id']})
                if message.get('status') != 'READY':
                    report['message_error'] = message.get('status')
                    break
                report['message_read'] = True
                attachment = next((a for a in message.get('attachments', [])
                                   if a['name'].lower().endswith('.pdf')), None)
                if attachment:
                    pdf = await call('get_attachment', {'message_id': chosen['id'],
                                                       'reference': attachment['reference']})
                    report['pdf'] = pdf.get('status')
                    if pdf.get('status') == 'READY':
                        report['pdf_bytes'] = pdf['bytes']
                    break
            digest = hashlib.sha256(json.dumps(versions(second), sort_keys=True).encode()).hexdigest()
            return report, digest


async def main() -> int:
    """Run two independent MCP processes and report only aggregate evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--school', required=True)
    parser.add_argument('--since', type=date.fromisoformat, default=date.today().replace(day=1))
    parser.add_argument('--download-host', action='append', default=[])
    args = parser.parse_args()
    try:
        first, first_digest = await run_once(args.school, args.since.isoformat(), args.download_host)
        print(json.dumps({'run': 1, **first}), flush=True)
        if first.get('auth') != 'READY' or not first_digest:
            return 1
        second, second_digest = await run_once(args.school, args.since.isoformat(), args.download_host)
        print(json.dumps({'run': 2, **second,
                          'same_after_restart': bool(second_digest) and first_digest == second_digest}), flush=True)
        passed = all(report.get('auth') == 'READY' and report.get('message_read')
                     and report.get('pdf') == 'READY' and not report.get('message_error')
                     for report in (first, second))
        return 0 if passed and second_digest else 1
    except Exception:
        print(json.dumps({'error': 'MCP_PROBE_FAILED'}), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))

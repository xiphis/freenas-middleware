from time import sleep

import pytest

from auto_config import ha, password, user
from middlewared.test.integration.utils import call, ssh
from middlewared.test.integration.utils.client import truenas_server


SYSLOG_CONF = '/etc/syslog-ng/syslog-ng.conf'

# ---------------------------------------
# ---------- utility functions ----------
# ---------------------------------------


def do_syslog(ident, message, facility='syslog.LOG_USER', priority='syslog.LOG_INFO'):
    """
    This generates a syslog message on the TrueNAS server we're currently testing.
    We don't need to override IP addr or creds because we are not a syslog target.
    """
    cmd = 'python3 -c "import syslog;'
    cmd += f'syslog.openlog(ident=\\\"{ident}\\\", facility={facility});'
    cmd += f'syslog.syslog({priority},\\\"{message}\\\");syslog.closelog()"'
    ssh(cmd)


def check_syslog(log_path, message, target_user=user, target_passwd=password, remote=False, timeout=30):
    """
    Common function to check whether a particular message exists in a log file.
    This will be used to check local and remote syslog servers.

    Current implementation performs simple grep through the log file, and so
    onus is on test developer to not under-specify `message` in order to avoid
    false positives.
    """
    if remote:
        assert ha is True, 'remote option is for HA only'

    target_ip = truenas_server.ip if not remote else truenas_server.ha_ips()['standby']
    sleep_time = 1
    while timeout > 0:
        found = ssh(
            f'grep -R "{message}" {log_path}',
            check=False,
            user=target_user,
            password=target_passwd,
            ip=target_ip
        )
        if not found:
            sleep(sleep_time)
            timeout -= sleep_time
        else:
            return found


def check_syslog_state(expected_state='active'):
    """Confirm syslog-ng is in requested state."""
    syslog_state = ssh('systemctl is-active syslog-ng').strip()
    assert syslog_state == expected_state

# -----------------------------------
# ------------ fixtures -------------
# -----------------------------------


@pytest.fixture
def erase_syslogservers():
    yield
    call('system.advanced.update', {'syslogservers': []})
    check_syslog_state()


@pytest.fixture
def tls_cert(erase_syslogservers):
    """Placeholder for adding remote certs and Restore syslog to default after testing"""
    truenas_default_id = 1
    yield truenas_default_id


# -----------------------------------
# -------------- tests --------------
# -----------------------------------


@pytest.mark.parametrize('params', [
    {
        'ident': 'iscsi-scstd',
        'msg': 'ZZZZ: random scst test',
        'path': '/var/log/scst.log',
    },
    {
        'ident': 'iscsi-scstd',
        'msg': 'ZZZZ: random scst test',
        'path': '/var/log/scst.log',  # This is just to make sure our exclude filter works as intended
    },
])
def test_local_syslog_filter(params):
    """
    This test validates that our syslog-ng filters are correctly placing
    messages into their respective paths in /var/log
    """
    do_syslog(
        params['ident'],
        params['msg'],
        params.get('facility', 'syslog.LOG_USER'),
        params.get('priority', 'syslog.LOG_INFO')
    )
    assert check_syslog(params['path'], params['msg'], timeout=10)
    check_syslog_state()


@pytest.mark.parametrize('log_path', [
    '/var/log/messages',
    '/var/log/syslog',
    '/var/log/daemon.log'
])
def test_filter_leak(log_path):
    """
    This test validates that our exclude filter works properly and that
    particularly spammy applications aren't polluting useful logs.
    """
    results = ssh(f'grep -R "ZZZZ:" {log_path}', complete_response=True, check=False)
    assert results['result'] is False, str(results['result'])
    check_syslog_state()


def test_set_remote_syslog(erase_syslogservers):
    """
    Basic test to validate that setting a remote syslog target
    doesn't break syslog-ng config
    """
    data = call('system.advanced.update', {'syslogservers': [{'host': '127.0.0.1'}]})
    assert data['syslogservers'][0]['host'] == '127.0.0.1'
    call('service.control', 'RESTART', 'syslogd', {'silent': False}, job=True)


def test_set_multiple_remote_syslog(erase_syslogservers):
    """
    Test to validate that setting multiple remote syslog targets
    doesn't break syslog-ng config and generates correct destinations
    """
    servers = [
        {'host': '127.0.0.1', 'transport': 'TCP', 'tls_certificate': None},
        {'host': '192.168.1.100:5514', 'transport': 'UDP', 'tls_certificate': None}
    ]
    data = call('system.advanced.update', {'syslogservers': servers})

    # Verify the servers were set correctly
    assert data['syslogservers'] == servers

    # Verify multiple destination blocks are generated in config
    conf = ssh(f'cat {SYSLOG_CONF}', complete_response=True)
    assert conf['result'] is True

    # Count destination blocks - should have loghost0 and loghost1
    num_remotes = conf['output'].count('destination loghost')
    assert num_remotes == 2, conf['output']


def test_remote_syslog_function(erase_syslogservers):
    """End-to-end validation of remote syslog using localhost as the "remote" destination.

    Testing on a remote system would be better, e.g. by using the standby node on HA, but this is the best we can do on
    Jenkins for now.

    """
    remote_port = 611
    remote_ip = f'127.0.0.1:{remote_port}'
    test_log = '/var/log/remote_log.txt'

    data = call('system.advanced.update', {'syslogservers': [{'host': remote_ip, 'transport': 'TCP'}]})
    assert data['syslogservers'] == [{'host': remote_ip, 'transport': 'TCP', 'tls_certificate': None}]
    check_syslog_state()

    # Configure to listen for TCP syslog messages on port 611 and log them to `test_log`.
    # This temporary configuration is removed by `erase_syslogservers` on test completion.
    server_config = (
        'source s_test_remote {\n'
        '  network(\n'
        '    ip(0.0.0.0)\n'
        f'    port({remote_port})\n'
        '    transport(tcp)\n'
        '  );\n'
        '};\n\n'

        'destination d_test_remote {\n'
        f'  file({test_log});\n'
        '};\n\n'

        'log { source(s_test_remote); destination(d_test_remote); };'
    )
    # Appy configuration without regenerating SYSLOG_CONF
    ssh(f'echo {server_config!r} >> {SYSLOG_CONF} && systemctl restart syslog-ng', timeout=10)

    do_syslog('CANARY', 'In a coal mine')  #savethecanaries
    assert check_syslog(test_log, 'In a coal mine', timeout=10)


@pytest.mark.parametrize('testing', ['TLS transport', 'Mutual TLS'])
def test_remote_syslog_with_TLS(tls_cert, testing):
    """
    Confirm expected settings in syslog-ng.conf when selecting TLS transport.
    NOTE: This test does NOT confirm end-to-end functionality.
    TODO: Add remote syslog server to enable end-to-end testing:
            * Mutual TLS: Add client cert,key and CA from remote syslog server
            (For testing purposes use 'truenas_default' cert)
    The tls_cert fixture performs syslog cleanup.
    """
    remote = '127.0.0.1'
    port = '5140'
    transport = 'TLS'

    # Fields to check for in the resulting syslog-ng.conf file
    test_tls = [remote, f'port({port})', 'transport(tls)', 'ca-file("/etc/ssl/certs/ca-certificates.crt")']
    tls_payload = {'host': f'{remote}:{port}', 'transport': transport}

    if testing == 'Mutual TLS':
        test_tls += [
            'key-file("/etc/certificates/truenas_default.key")',
            'cert-file("/etc/certificates/truenas_default.crt")'
        ]
        tls_payload['tls_certificate'] = tls_cert

    data = call('system.advanced.update', {'syslogservers': [tls_payload]})
    assert data['syslogservers'][0]['transport'] == 'TLS'

    conf = ssh(
        f'grep -A10 "destination loghost" {SYSLOG_CONF}',
        complete_response=True, check=False
    )
    assert conf['result'] is True, 'Missing remote entry'

    # Assert syslog-ng.conf contains all fields in `test_tls`
    file_lines = conf['output'].splitlines()
    for item in test_tls:
        assert any(item in s for s in file_lines)

"""Observe a bounded monitor's lifecycle without restricting post-unload tests."""
from datetime import datetime
import json
from pathlib import Path
import subprocess
import time

RESERVE_SECONDS = 5
_ACTIVE = []


def start_monitor(command, **kwargs):
    if '--duration' not in command or '--out' not in command:
        raise ValueError('A monitored test needs explicit --duration and --out')
    duration = int(command[command.index('--duration') + 1])
    if duration <= 0:
        raise ValueError('Monitor duration must be positive')
    records = Path(command[command.index('--out') + 1])
    started = time.monotonic()
    monitor = subprocess.Popen(command, **kwargs)
    monitor._driver_window = dict(
        started=started, duration=duration, records=records,
        console=records.with_name('console.log'), complete=False,
        phases=[], checks_outside_loaded=0, post_cleanup_checks=0,
    )
    _ACTIVE.append(monitor)
    return monitor


def _write_observation(monitor):
    window = monitor._driver_window
    observation = window['last_observation']
    proof = dict(
        classification='monitor-lifecycle-observation',
        functional_phase_finished_while_loaded=(
            observation['phase'] == 'loaded' and window['checks_outside_loaded'] == 0),
        finished_at=datetime.now().astimezone().isoformat(timespec='microseconds'),
        monitor_exit_at_finish=observation['monitor_exit'],
        duration_seconds=window['duration'], remaining_seconds=observation['remaining_seconds'],
        reserve_seconds=RESERVE_SECONDS, elapsed_seconds=observation['elapsed_seconds'],
        budget_sufficient=observation['budget_sufficient'],
        observed_phase=observation['phase'], observed_phases=window['phases'],
        checks_outside_loaded=window['checks_outside_loaded'],
        post_cleanup_checks=window['post_cleanup_checks'],
    )
    window['records'].with_name('driver-window.json').write_text(
        json.dumps(proof, indent=2), encoding='utf-8')


def check_monitor(monitor, minimum_seconds=0):
    """Record state and remaining time; shutdown and budget expiry are not errors."""
    window = monitor._driver_window
    elapsed = time.monotonic() - window['started']
    remaining = window['duration'] - elapsed
    code = monitor.poll()
    console = window['console'].read_text(errors='replace') if window['console'].exists() else ''
    if code is not None:
        phase = 'exited'
    elif 'Shutting down.' in console or 'Duration elapsed, stopping' in console:
        phase = 'stopping'
    elif 'Running for ' in console:
        phase = 'loaded'
    else:
        phase = 'starting'
    window['last_observation'] = dict(
        phase=phase, monitor_exit=code, remaining_seconds=remaining, elapsed_seconds=elapsed,
        budget_sufficient=remaining >= RESERVE_SECONDS + minimum_seconds,
    )
    if phase not in window['phases']:
        window['phases'].append(phase)
    if phase != 'loaded':
        window['checks_outside_loaded'] += 1
    if window['complete']:
        window['post_cleanup_checks'] += 1
        _write_observation(monitor)
    return remaining


def check_active(minimum_seconds=0):
    for monitor in _ACTIVE:
        if not monitor._driver_window['complete']:
            check_monitor(monitor, minimum_seconds)


def wait_for_cleanup(monitor, **kwargs):
    """Record the current phase and let --duration close the owned driver safely."""
    window = monitor._driver_window
    try:
        if not window['complete']:
            check_monitor(monitor)
            window['complete'] = True
            _write_observation(monitor)
    finally:
        # An observation failure must not skip the owner's normal cleanup.
        code = monitor.wait(**kwargs)
    return code

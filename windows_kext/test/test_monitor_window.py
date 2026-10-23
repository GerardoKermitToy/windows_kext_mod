"""Offline lifecycle observations; post-unload checks must remain allowed."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import monitor_window


class MonitorWindowTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.console = self.root / 'console.log'
        self.console.write_text('Running for 20 second(s), then stopping.\n')
        self.command = ['kext_monitor.exe', '--duration', '20', '--out', str(self.root / 'records.log')]
        self.monitor = Mock(returncode=None)
        self.monitor.poll.return_value = None
        self.monitor.wait.return_value = 0
        self.process_patch = patch.object(monitor_window.subprocess, 'Popen', return_value=self.monitor)
        self.process_patch.start()
        self.addCleanup(self.process_patch.stop)
        self.clock_patch = patch.object(monitor_window.time, 'monotonic', return_value=100.0)
        self.clock = self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.active_patch = patch.object(monitor_window, '_ACTIVE', [])
        self.active_patch.start()
        self.addCleanup(self.active_patch.stop)

    def start(self):
        return monitor_window.start_monitor(self.command)

    def proof(self):
        return json.loads((self.root / 'driver-window.json').read_text())

    def test_requires_explicit_duration_and_record_path(self):
        for command in (['kext_monitor.exe'], ['kext_monitor.exe', '--duration', '20']):
            with self.subTest(command=command), self.assertRaises(ValueError):
                monitor_window.start_monitor(command)
        monitor_window.subprocess.Popen.assert_not_called()

    def test_duration_must_be_positive(self):
        for duration in ('0', '-1'):
            command = self.command.copy()
            command[command.index('--duration') + 1] = duration
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                monitor_window.start_monitor(command)
        monitor_window.subprocess.Popen.assert_not_called()

    def test_short_bounded_monitor_is_allowed(self):
        self.command[self.command.index('--duration') + 1] = '1'
        monitor = self.start()
        self.assertEqual(monitor_window.check_monitor(monitor), 1.0)
        self.assertFalse(monitor._driver_window['last_observation']['budget_sufficient'])

    def test_ready_window_records_bounded_work(self):
        monitor = self.start()
        self.clock.return_value = 105.0
        self.assertEqual(monitor_window.check_monitor(monitor, minimum_seconds=4), 15.0)
        monitor_window.check_active(minimum_seconds=4)
        self.assertTrue(monitor._driver_window['last_observation']['budget_sufficient'])

    def test_insufficient_budget_does_not_reject_new_work(self):
        monitor = self.start()
        self.clock.return_value = 112.0
        self.assertEqual(monitor_window.check_monitor(monitor, minimum_seconds=4), 8.0)
        monitor_window.check_active(minimum_seconds=4)
        self.assertFalse(monitor._driver_window['last_observation']['budget_sufficient'])

    def test_expired_budget_is_observed_without_rejection(self):
        monitor = self.start()
        self.clock.return_value = 123.0
        self.assertEqual(monitor_window.check_monitor(monitor), -3.0)
        monitor_window.check_active()
        self.assertFalse(monitor._driver_window['last_observation']['budget_sufficient'])

    def test_process_exit_does_not_reject_work(self):
        monitor = self.start()
        for code in (0, 1):
            with self.subTest(code=code):
                monitor.poll.return_value = code
                monitor_window.check_monitor(monitor)
                self.assertEqual(monitor._driver_window['last_observation']['phase'], 'exited')
                self.assertEqual(monitor._driver_window['last_observation']['monitor_exit'], code)

    def test_starting_and_stopping_are_recorded_not_forbidden(self):
        monitor = self.start()
        for text, phase in (
                ('Loading driver\n', 'starting'),
                ('Running for 20 second(s)\nShutting down.\n', 'stopping'),
                ('Running for 20 second(s)\nDuration elapsed, stopping...\n', 'stopping')):
            with self.subTest(text=text):
                self.console.write_text(text)
                monitor_window.check_monitor(monitor)
                self.assertEqual(monitor._driver_window['last_observation']['phase'], phase)

    def test_cleanup_records_state_before_waiting(self):
        monitor = self.start()
        self.clock.return_value = 108.0

        def waited(**kwargs):
            proof = self.proof()
            self.assertTrue(proof['functional_phase_finished_while_loaded'])
            self.assertEqual(proof['remaining_seconds'], 12.0)
            self.assertEqual(proof['elapsed_seconds'], 8.0)
            return 0

        monitor.wait.side_effect = waited
        self.assertEqual(monitor_window.wait_for_cleanup(monitor, timeout=60), 0)
        monitor.wait.assert_called_once_with(timeout=60)
        monitor_window.check_monitor(monitor)
        monitor_window.check_active()

    def test_cleanup_after_exit_is_not_a_harness_failure(self):
        monitor = self.start()
        self.clock.return_value = 123.0
        monitor.poll.return_value = 0
        self.assertEqual(monitor_window.wait_for_cleanup(monitor, timeout=60), 0)
        monitor.wait.assert_called_once_with(timeout=60)
        proof = self.proof()
        self.assertFalse(proof['functional_phase_finished_while_loaded'])
        self.assertEqual(proof['classification'], 'monitor-lifecycle-observation')
        self.assertEqual(proof['observed_phase'], 'exited')

    def test_post_cleanup_checks_update_loaded_observation(self):
        monitor = self.start()
        monitor_window.wait_for_cleanup(monitor, timeout=60)
        self.assertTrue(self.proof()['functional_phase_finished_while_loaded'])
        monitor.poll.return_value = 0
        self.clock.return_value = 123.0
        monitor_window.check_monitor(monitor)
        proof = self.proof()
        self.assertFalse(proof['functional_phase_finished_while_loaded'])
        self.assertEqual(proof['post_cleanup_checks'], 1)
        self.assertEqual(proof['observed_phases'], ['loaded', 'exited'])

    def test_an_earlier_unloaded_check_is_not_hidden_by_a_later_ready_banner(self):
        monitor = self.start()
        self.console.write_text('Loading driver\n')
        monitor_window.check_monitor(monitor)
        self.console.write_text('Running for 20 second(s)\n')
        monitor_window.wait_for_cleanup(monitor, timeout=60)
        self.assertFalse(self.proof()['functional_phase_finished_while_loaded'])
        self.assertEqual(self.proof()['checks_outside_loaded'], 1)

    def test_nonzero_monitor_exit_is_returned(self):
        monitor = self.start()
        monitor.wait.return_value = 7
        self.assertEqual(monitor_window.wait_for_cleanup(monitor, timeout=60), 7)

    def test_observation_write_failure_still_waits_for_cleanup(self):
        monitor = self.start()
        with patch.object(Path, 'write_text', side_effect=OSError('disk unavailable')):
            with self.assertRaises(OSError):
                monitor_window.wait_for_cleanup(monitor, timeout=60)
        monitor.wait.assert_called_once_with(timeout=60)

    def test_wait_timeout_does_not_terminate_monitor(self):
        monitor = self.start()
        monitor.wait.side_effect = monitor_window.subprocess.TimeoutExpired('kext_monitor', 60)
        with self.assertRaises(monitor_window.subprocess.TimeoutExpired):
            monitor_window.wait_for_cleanup(monitor, timeout=60)
        monitor.terminate.assert_not_called()
        monitor.kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()

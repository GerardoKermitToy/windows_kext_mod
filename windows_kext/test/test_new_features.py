"""Offline coverage for scoped verdict modes and post-unload shutdown checks."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import new_features


class NewFeatureCommandTests(unittest.TestCase):
    def args(self, mode='shutdown', ipv6=False, verdict='permanent-accept'):
        command = ['--mode', mode, '--verdict', verdict, '--output', 'unused-output']
        if ipv6:
            command.append('--ipv6')
        return new_features.argument_parser().parse_args(command)

    def test_all_modes_are_available(self):
        for mode in ('close', 'delay', 'suspend', 'shutdown'):
            with self.subTest(mode=mode):
                self.assertEqual(self.args(mode).mode, mode)

    def test_shutdown_is_bounded_scoped_and_longer_than_monitor(self):
        for ipv6 in (False, True):
            for verdict in ('accept', 'permanent-accept'):
                with self.subTest(ipv6=ipv6, verdict=verdict):
                    args = self.args(ipv6=ipv6, verdict=verdict)
                    ip = '::1' if ipv6 else '127.0.0.1'
                    command, duration, delay = new_features.monitor_command(args, ip, 54321, Path('records.log'))
                    self.assertEqual(duration, 7)
                    self.assertEqual(delay, 60000)
                    self.assertGreater(delay, duration * 1000)
                    self.assertEqual(command[command.index('--duration') + 1], str(duration))
                    self.assertEqual(command[command.index('--verdict-delay-ms') + 1], str(delay))
                    expected = '[::1]:54321' if ipv6 else '127.0.0.1:54321'
                    self.assertEqual(command[command.index('--match') + 1], expected)
                    self.assertEqual(command[command.index('--verdict') + 1], verdict)
                    self.assertIn('--suspend-pid-on-verdict-delay', command)
                    self.assertEqual(command[-1], str(args.driver.resolve()))

    def test_other_modes_keep_existing_timing_and_suspension(self):
        for mode, duration, delay, suspended in (
                ('close', 260, 1500, False), ('delay', 40, 300, False), ('suspend', 40, 300, True)):
            with self.subTest(mode=mode):
                command, actual_duration, actual_delay = new_features.monitor_command(
                    self.args(mode), '127.0.0.1', 54321, Path('records.log'))
                self.assertEqual((actual_duration, actual_delay), (duration, delay))
                self.assertEqual('--suspend-pid-on-verdict-delay' in command, suspended)

    def test_fresh_output_is_required_before_monitor_or_sockets(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args()
            args.output = Path(directory)
            with patch.object(new_features, 'driver_owners', return_value=''), \
                    patch.object(new_features, 'start_monitor') as start:
                with self.assertRaises(FileExistsError):
                    new_features.run(args)
                start.assert_not_called()

    def test_existing_driver_owner_is_not_taken_over(self):
        with patch.object(new_features, 'driver_owners', return_value='monitor=1234'), \
                patch.object(new_features, 'start_monitor') as start:
            with self.assertRaisesRegex(AssertionError, 'Existing driver owner'):
                new_features.run(self.args())
            start.assert_not_called()


class ShutdownCompletionTests(unittest.TestCase):
    def setUp(self):
        self.monitor = Mock()
        self.child = Mock()
        self.child.meta = {'pid': 456}
        self.child.process.poll.return_value = None
        self.child.next.return_value = {'alive': True, 'connected': True}
        self.connections = [{'id': 9}, {'id': 10}]
        self.records = (
            '[SUSPEND] pid=456 held for delayed verdict id=9 generation=1\n'
            'Duration elapsed, stopping...\n'
            '[RESUME] pid=456 at monitor shutdown (pending verdicts cancelled)\n'
        )
        self.wait_patch = patch.object(new_features, 'wait_for_cleanup', return_value=0)
        self.wait = self.wait_patch.start()
        self.addCleanup(self.wait_patch.stop)
        self.observe_patch = patch.object(new_features, 'check_monitor')
        self.observe = self.observe_patch.start()
        self.addCleanup(self.observe_patch.stop)

    def finish(self):
        return new_features.finish_shutdown(
            self.monitor, self.child, self.connections, lambda: self.records, 7)

    def test_child_is_checked_after_monitor_has_cleaned_up(self):
        order = []
        self.wait.side_effect = lambda *a, **kw: order.append('cleanup') or 0
        self.observe.side_effect = lambda *a, **kw: order.append('observe-exit')
        self.child.next.side_effect = lambda **kw: order.append('child-resumed') or {'alive': True}
        code, resumed = self.finish()
        self.assertEqual(code, 0)
        self.assertTrue(resumed['alive'])
        self.assertEqual(order, ['cleanup', 'observe-exit', 'child-resumed'])
        self.wait.assert_called_once_with(self.monitor, timeout=32)
        self.child.next.assert_called_once_with(timeout=12)

    def test_nonzero_monitor_exit_is_not_a_pass(self):
        self.wait.return_value = 1
        with self.assertRaisesRegex(AssertionError, 'Monitor failed'):
            self.finish()
        self.child.next.assert_not_called()

    def test_resume_without_a_held_child_is_not_a_pass(self):
        self.records = self.records.split('\n', 1)[1]
        with self.assertRaisesRegex(AssertionError, 'not suspended'):
            self.finish()

    def test_missing_or_premature_shutdown_resume_is_not_a_pass(self):
        for records in (
                'Duration elapsed, stopping...\n',
                self.records.replace('at monitor shutdown (pending verdicts cancelled)', 'after verdict id=9'),
                self.records.replace('Duration elapsed, stopping...\n', '') + 'Duration elapsed, stopping...\n'):
            with self.subTest(records=records):
                self.records = records if '[SUSPEND]' in records else '[SUSPEND] pid=456 held\n' + records
                with self.assertRaisesRegex(AssertionError, 'Missing shutdown resume'):
                    self.finish()

    def test_any_cancelled_request_being_sent_is_not_a_pass(self):
        for request_id in (9, 10):
            original = self.records
            with self.subTest(request_id=request_id):
                self.records += f'[VERDICT] id={request_id} -> verdict PermanentAccept sent\n'
                with self.assertRaisesRegex(AssertionError, 'Cancelled delayed verdict'):
                    self.finish()
            self.records = original

    def test_other_request_ids_are_not_confused_with_cancelled_ids(self):
        self.records += '[VERDICT] id=90 -> verdict PermanentAccept sent\n'
        self.assertEqual(self.finish()[0], 0)

    def test_an_exited_child_is_not_evidence_of_resume(self):
        self.child.process.poll.return_value = 0
        with self.assertRaises(AssertionError):
            self.finish()

    def test_no_child_progress_fails_instead_of_becoming_a_shutdown_pass(self):
        self.child.next.side_effect = AssertionError('live child did not progress')
        with self.assertRaisesRegex(AssertionError, 'did not progress'):
            self.finish()

    def test_socket_error_can_be_observed_after_pending_connection_is_cancelled(self):
        self.child.next.return_value = {'alive': True, 'error': 'connection cancelled', 'winerror': 10013}
        self.assertEqual(self.finish()[1]['winerror'], 10013)


if __name__ == '__main__':
    unittest.main()

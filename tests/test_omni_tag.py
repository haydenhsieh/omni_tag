import contextlib
import io
import unittest
from unittest.mock import Mock, patch

from omni_tag.cli import main, parser, run
from omni_tag.hardware import BusPirate, CommandTimeout, HardwareError, RC522, TagTimeout, crc_a


class Tests(unittest.TestCase):
    def test_cli_defaults_and_overrides(self):
        args = parser().parse_args(['--port', 'fake', 'set-uid', 'DEADBEEF', '--yes'])
        self.assertEqual(args.method, 'gen2')
        self.assertTrue(args.reset_aux)
        args = parser().parse_args(['--port', 'fake', '--no-reset-aux', 'set-uid',
                                    'DEADBEEF', '--method', 'gen1a', '--yes'])
        self.assertEqual(args.method, 'gen1a')
        self.assertFalse(args.reset_aux)
        self.assertTrue(parser().parse_args(['--port', 'fake', '--reset-aux', 'info']).reset_aux)

    def test_crc_reference_halt(self):
        self.assertEqual(crc_a(bytes.fromhex('5000')), bytes.fromhex('57cd'))
        self.assertEqual(crc_a(bytes.fromhex('3004')), bytes.fromhex('26ee'))

    def test_ack_requires_four_bits(self):
        RC522.expect_ack(b'\x0a', 4)
        for reply, bits in ((b'\x0a', 8), (b'\x00', 4), (b'', 0)):
            with self.assertRaises(HardwareError):
                RC522.expect_ack(reply, bits)

    def test_block_read_rejects_corrupt_crc(self):
        reader = RC522(None)
        reader.frame = Mock(return_value=(bytes(18), 144))
        with self.assertRaises(HardwareError):
            reader.read_block(4)

    def test_uid_preserves_manufacturer_bytes_and_reselects(self):
        reader = Mock()
        old = bytes.fromhex('11223344')
        original = old + b'\x44' + bytes(range(11))
        reader.select.side_effect = [(old, b'\x04\x00', 8),
                                     (bytes.fromhex('deadbeef'), b'\x04\x00', 8)]
        reader.read_block.return_value = original
        args = parser().parse_args(['--port', 'fake', 'set-uid', 'DEADBEEF', '--method', 'gen1a', '--yes'])
        with contextlib.redirect_stdout(io.StringIO()):
            run(args, reader)
        reader.write_block.assert_called_once_with(0, bytes.fromhex('deadbeef22') + original[5:])
        self.assertEqual(reader.select.call_count, 2)
        reader.unlock.assert_called_once()

    def test_gen2_uid_authenticates_and_preserves_reported_block(self):
        original = bytes.fromhex('F113B255050804006263646566676869')
        for key_type in ('A', 'B'):
            with self.subTest(key_type=key_type):
                reader = Mock()
                reader.select.side_effect = [(original[:4], b'\x04\x00', 8),
                                             (bytes.fromhex('DEADBEEF'), b'\x04\x00', 8)]
                reader.read_block.return_value = original
                args = parser().parse_args(['--port', 'fake', 'set-uid', 'DEADBEEF',
                                            '--key', 'A0A1A2A3A4A5',
                                            '--key-type', key_type, '--yes'])
                with contextlib.redirect_stdout(io.StringIO()):
                    run(args, reader)
                reader.unlock.assert_not_called()
                reader.authenticate.assert_called_once_with(
                    0, bytes.fromhex('A0A1A2A3A4A5'), original[:4], key_type == 'B')
                reader.write_block.assert_called_once_with(
                    0, bytes.fromhex('DEADBEEF22') + original[5:])

    def test_gen2_auth_failure_prevents_uid_write(self):
        reader = Mock()
        reader.select.return_value = (bytes.fromhex('F113B255'), b'\x04\x00', 8)
        reader.authenticate.side_effect = HardwareError('Authentication failed')
        args = parser().parse_args(['--port', 'fake', 'set-uid', 'DEADBEEF', '--method', 'gen2', '--yes'])
        with self.assertRaisesRegex(HardwareError, 'Gen2 authentication for block 0'):
            run(args, reader)
        reader.read_block.assert_not_called()
        reader.write_block.assert_not_called()
        reader.unlock.assert_not_called()

    def test_gen2_uid_rejects_mismatched_block_before_writing(self):
        reader = Mock()
        reader.select.return_value = (bytes.fromhex('F113B255'), b'\x04\x00', 8)
        reader.read_block.return_value = bytes(16)
        args = parser().parse_args(['--port', 'fake', 'set-uid', 'DEADBEEF', '--method', 'gen2', '--yes'])
        with self.assertRaisesRegex(HardwareError, 'does not match selected UID/BCC'):
            run(args, reader)
        reader.write_block.assert_not_called()

    def test_write_verification_failure(self):
        reader = RC522(None)
        reader.frame = Mock(return_value=(b'\x0a', 4))
        reader.read_block = Mock(return_value=bytes(16))
        with self.assertRaises(HardwareError):
            reader.write_block(4, b'a' * 16)

    def test_guards_before_opening_serial(self):
        for tail in (['set-uid', '11223344'],
                     ['write-block', '0', '00' * 16, '--yes'],
                     ['write-block', '3', '00' * 16, '--yes'],
                     ['write-block', '143', '00' * 16, '--yes']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
                main(['--port', 'fake'] + tail)
            self.assertEqual(result.exception.code, 2)

    def test_spi_chunks_and_cs(self):
        port = Mock()
        # low-CS ACK, bulk ACK/data, bulk ACK/data, high-CS ACK
        port.read.side_effect = [b'\x01', b'\x01', bytes(range(16)),
                                 b'\x01', b'\xaa\xbb', b'\x01']
        bus = BusPirate(port)
        self.assertEqual(bus.transfer(bytes(range(18))), bytes(range(16)) + b'\xaa\xbb')
        self.assertEqual([call.args[0] for call in port.write.call_args_list],
                         [b'\x02', b'\x1f', bytes(range(16)), b'\x11', bytes([16, 17]), b'\x03'])

    def test_aux_reset_startup_and_cleanup(self):
        for power, reset_aux, expected in (
            (False, False, [0x41]), (True, False, [0x49]),
            (False, True, [0x41, 0x43]), (True, True, [0x49, 0x4B]),
        ):
            with self.subTest(power=power, reset_aux=reset_aux):
                port = Mock()
                port.read.side_effect = [b'BBIO1', b'SPI1', b'BBIO1']
                bus = BusPirate(port, power=power, reset_aux=reset_aux)
                bus.ack = Mock()
                with patch('omni_tag.hardware.time.sleep') as sleep:
                    bus.start()
                self.assertEqual([c.args[0] for c in bus.ack.call_args_list],
                                 [0x8A, 0x61] + expected)
                self.assertEqual([c.args[0] for c in sleep.call_args_list],
                                 [0.01, 0.05] if reset_aux else [0.05])
                bus.close()
                bus.ack.assert_called_with(0x41)
                port.close.assert_called_once()

    def test_partial_serial_reads(self):
        port = Mock()
        port.read.side_effect = [b'S', b'PI', b'1']
        self.assertEqual(BusPirate(port).read(4), b'SPI1')

    def test_command_timeout_reports_registers_and_stops_command(self):
        reader = RC522(None)
        reader.write = Mock()
        reader.read = Mock(side_effect=[0x40, 0x00, 0x21, 0])
        with patch('omni_tag.hardware.time.monotonic', side_effect=[0, 0, 3]):
            with self.assertRaisesRegex(HardwareError, 'IRQ=0x40.*ErrorReg=0x00.*Status1=0x21'):
                reader.exchange(b'\x40', bits=7)
        self.assertEqual([c.args for c in reader.write.call_args_list[-2:]],
                         [(0x0D, 7), (0x01, 0)])

    def test_halt_ignores_only_tag_timeout(self):
        reader = RC522(None)
        reader.read = Mock(return_value=0)
        reader.write = Mock()
        reader.frame = Mock(side_effect=HardwareError('RC522 command timeout'))
        reader.exchange = Mock()
        with self.assertRaisesRegex(HardwareError, 'Gen1A HALT: RC522 command timeout'):
            reader.unlock()
        reader.exchange.assert_not_called()
        reader.frame.side_effect = TagTimeout('Tag timeout; no response')
        reader.exchange.return_value = (b'\x0a', 4)
        reader.unlock()
        self.assertEqual([c.args for c in reader.exchange.call_args_list],
                         [(b'\x40',), (b'\x43',)])

    def test_halt_accepts_transmitted_silence_with_host_timeout(self):
        reader = RC522(None)
        reader.read = Mock(return_value=0)
        reader.write = Mock()
        reader.frame = Mock(side_effect=CommandTimeout(0x0C, 0x44, 0, 0x21, 0))
        reader.exchange = Mock(return_value=(b'\x0a', 4))
        reader.unlock()
        self.assertEqual(reader.exchange.call_count, 2)

    def test_halt_rejects_failed_transmission_or_partial_response(self):
        for irq, error, fifo in ((0, 0, 0), (0x44, 1, 0), (0x44, 0, 1),
                                 (0x64, 0, 0), (0x46, 0, 0)):
            with self.subTest(irq=irq, error=error, fifo=fifo):
                reader = RC522(None)
                reader.read = Mock(return_value=0)
                reader.write = Mock()
                reader.frame = Mock(side_effect=CommandTimeout(0x0C, irq, error, 0x21, fifo))
                reader.exchange = Mock()
                with self.assertRaisesRegex(HardwareError, 'Gen1A HALT:'):
                    reader.unlock()
                reader.exchange.assert_not_called()

    def test_halt_rejects_actual_response(self):
        reader = RC522(None)
        reader.read = Mock(return_value=0)
        reader.write = Mock()
        reader.frame = Mock(return_value=(b'\x0a', 4))
        reader.exchange = Mock()
        with self.assertRaisesRegex(HardwareError, 'unexpected response'):
            reader.unlock()
        reader.exchange.assert_not_called()

    def test_unlock_timeouts_are_not_treated_as_success(self):
        for failed_step in (0, 1):
            reader = RC522(None)
            reader.read = Mock(return_value=0)
            reader.write = Mock()
            reader.frame = Mock(side_effect=TagTimeout('Tag timeout'))
            reader.exchange = Mock(side_effect=(
                [CommandTimeout(0x0C, 0x44, 0, 0x21, 0)] if failed_step == 0 else
                [(b'\x0a', 4), CommandTimeout(0x0C, 0x44, 0, 0x21, 0)]))
            with self.assertRaisesRegex(HardwareError, f'Gen1A unlock 0x{(0x40, 0x43)[failed_step]:02X}'):
                reader.unlock()

    def test_uid_unlock_failure_reports_stage_and_does_not_write(self):
        reader = Mock()
        reader.select.return_value = (bytes.fromhex('11223344'), b'\x04\x00', 8)
        reader.unlock.side_effect = HardwareError('Gen1A HALT: RC522 command timeout')
        args = parser().parse_args(['--port', 'fake', 'set-uid', 'DEADBEEF', '--method', 'gen1a', '--yes'])
        with self.assertRaisesRegex(HardwareError, 'unlock before UID write: Gen1A HALT'):
            run(args, reader)
        reader.write_block.assert_not_called()

    def test_init_waits_until_reset_completes_and_verifies_settings(self):
        reader = RC522(None)
        registers = {0x37: 0x92, 0x14: 0x80}
        reset_reads = iter([0x10, 0x0F, 0])

        def read(reg):
            return next(reset_reads) if reg == 1 else registers.get(reg, 0)

        def write(reg, value):
            registers[reg] = value

        reader.read = Mock(side_effect=read)
        reader.write = Mock(side_effect=write)
        with patch('omni_tag.hardware.time.sleep'):
            self.assertEqual(reader.init(), 0x92)
        self.assertEqual(registers[0x14], 0x83)
        self.assertEqual(registers[0x2A], 0x8D)

    def test_init_rejects_reported_reset_default_registers(self):
        reader = RC522(None)
        reader.write = Mock()
        defaults = {0x01: 0x20, 0x37: 0x12, 0x11: 0x3F, 0x14: 0x80}
        reader.read = Mock(side_effect=lambda reg: defaults.get(reg, 0))
        with patch('omni_tag.hardware.time.sleep'):
            with self.assertRaisesRegex(HardwareError, 'configuration did not persist.*antenna outputs disabled'):
                reader.init()

    def test_init_rejects_stuck_reset_before_configuration(self):
        reader = RC522(None)
        reader.write = Mock()
        reader.read = Mock(return_value=0x10)
        with patch('omni_tag.hardware.time.sleep'):
            with self.assertRaisesRegex(HardwareError, 'reset did not complete'):
                reader.init()
        reader.write.assert_called_once_with(0x01, 0x0F)

    def test_reader_info_does_not_select_or_write_tag(self):
        reader = Mock()
        reader.diagnostics.return_value = {'VersionReg': '92', 'TxControlReg': '83'}
        args = parser().parse_args(['--port', 'fake', 'reader-info'])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            run(args, reader)
        self.assertIn('"VersionReg": "92"', output.getvalue())
        reader.select.assert_not_called()
        reader.write_block.assert_not_called()

    def test_wake_failure_identifies_selection_step(self):
        reader = RC522(None)
        reader.read = Mock(return_value=0)
        reader.write = Mock()
        reader.exchange = Mock(side_effect=CommandTimeout(0x0C, 0x44, 0, 0x21, 0))
        with self.assertRaisesRegex(HardwareError, r'WUPA \(wake card\): RC522 command timeout'):
            reader.select()

    def test_card_capacity_before_authentication(self):
        reader = Mock()
        reader.select.return_value = (bytes(4), b'\x04\x00', 8)
        args = parser().parse_args(['--port', 'fake', 'read-block', '64'])
        with self.assertRaises(HardwareError):
            run(args, reader)
        reader.authenticate.assert_not_called()


if __name__ == '__main__':
    unittest.main()

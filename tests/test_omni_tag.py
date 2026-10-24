import contextlib
import io
import unittest
from unittest.mock import Mock

from omni_tag.cli import main, parser, run
from omni_tag.hardware import BusPirate, HardwareError, RC522, crc_a


class Tests(unittest.TestCase):
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
        args = parser().parse_args(['--port', 'fake', 'set-uid', 'DEADBEEF', '--yes'])
        with contextlib.redirect_stdout(io.StringIO()):
            run(args, reader)
        reader.write_block.assert_called_once_with(0, bytes.fromhex('deadbeef22') + original[5:])
        self.assertEqual(reader.select.call_count, 2)
        reader.unlock.assert_called_once()

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

    def test_partial_serial_reads(self):
        port = Mock()
        port.read.side_effect = [b'S', b'PI', b'1']
        self.assertEqual(BusPirate(port).read(4), b'SPI1')

    def test_card_capacity_before_authentication(self):
        reader = Mock()
        reader.select.return_value = (bytes(4), b'\x04\x00', 8)
        args = parser().parse_args(['--port', 'fake', 'read-block', '64'])
        with self.assertRaises(HardwareError):
            run(args, reader)
        reader.authenticate.assert_not_called()


if __name__ == '__main__':
    unittest.main()

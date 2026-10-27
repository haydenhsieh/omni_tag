import argparse
import json
import sys
from functools import reduce
from operator import xor

from .hardware import BusPirate, HardwareError, RC522


def hex_bytes(value, size):
    try:
        data = bytes.fromhex(value.replace(':', '').replace('-', ''))
    except ValueError as error:
        raise argparse.ArgumentTypeError('Expected hexadecimal bytes') from error
    if len(data) != size:
        raise argparse.ArgumentTypeError(f'Expected {size} bytes ({size * 2} hex digits)')
    return data


def block_number(value):
    number = int(value, 0)
    if not 0 <= number <= 255:
        raise argparse.ArgumentTypeError('Block must be between 0 and 255')
    return number


def parser():
    p = argparse.ArgumentParser(description='Bus Pirate legacy SPI + RC522 MIFARE Classic tool')
    p.add_argument('--port', required=True, help='Serial device, e.g. /dev/ttyUSB0')
    p.add_argument('--baud', type=int, default=115200)
    p.add_argument('--power', action='store_true', help='Enable Bus Pirate onboard power (legacy hardware only)')
    p.add_argument('--reset-aux', action='store_true', help='Drive RC522 RST using Bus Pirate AUX')
    commands = p.add_subparsers(dest='command', required=True)
    commands.add_parser('info', help='Read reader version, UID, ATQA and SAK')
    for name in ('read-block', 'write-block'):
        sub = commands.add_parser(name)
        sub.add_argument('block', type=block_number)
        sub.add_argument('--magic', action='store_true', help='Use Gen1A backdoor instead of key authentication')
        sub.add_argument('--key', type=lambda s: hex_bytes(s, 6), default=bytes.fromhex('FFFFFFFFFFFF'))
        sub.add_argument('--key-type', choices=('A', 'B'), default='A')
        if name == 'write-block':
            sub.add_argument('data', type=lambda s: hex_bytes(s, 16))
            sub.add_argument('--yes', action='store_true', help='Confirm writing this block')
    sub = commands.add_parser('set-uid', help='Change a four-byte Gen1A UID, preserving the rest of block 0')
    sub.add_argument('uid', type=lambda s: hex_bytes(s, 4))
    sub.add_argument('--yes', action='store_true', help='Confirm UID change')
    return p


def run(args, reader):
    version = reader.init()
    uid, atqa, sak = reader.select()
    if args.command == 'info':
        print(json.dumps({'reader_version': f'{version:02X}', 'uid': uid.hex().upper(),
                          'atqa': atqa.hex().upper(), 'sak': f'{sak:02X}'}))
        return
    if sak not in (0x08, 0x09, 0x18):
        raise HardwareError('Block operations require a supported MIFARE Classic card')
    if args.command == 'set-uid':
        if len(uid) != 4:
            raise HardwareError('set-uid supports four-byte Gen1A cards only')
        reader.unlock()
        original = reader.read_block(0)
        if original[:4] != uid or original[4] != reduce(xor, uid):
            raise HardwareError('Block 0 does not match selected UID/BCC')
        updated = args.uid + bytes([reduce(xor, args.uid)]) + original[5:]
        reader.write_block(0, updated)
        # Cycle the RF field and verify actual anticollision UID, too.
        reader.stop()
        reader.init()
        actual, _, _ = reader.select()
        if actual != args.uid:
            raise HardwareError('Block written, but selected UID verification failed')
        print(f'UID changed: {uid.hex().upper()} -> {actual.hex().upper()}')
        return
    limit = {0x09: 20, 0x08: 64, 0x18: 256}[sak]
    if args.block >= limit:
        raise HardwareError(f'Block out of range for this card (0–{limit - 1})')
    if args.magic:
        reader.unlock()
    else:
        reader.authenticate(args.block, args.key, uid, args.key_type == 'B')
    if args.command == 'read-block':
        print(reader.read_block(args.block).hex().upper())
    else:
        reader.write_block(args.block, args.data)
        print(f'Block {args.block} written and verified')


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if args.command in ('write-block', 'set-uid') and not args.yes:
        p.error('Writing requires --yes')
    if args.command == 'write-block':
        trailer = args.block % 4 == 3 if args.block < 128 else (args.block - 128) % 16 == 15
        if args.block == 0 or trailer:
            p.error('write-block protects manufacturer and sector trailer blocks; use set-uid for UID changes')
    bus = None
    reader = None
    try:
        import serial
        bus = BusPirate(serial.Serial(args.port, args.baud, timeout=0.25, write_timeout=2), args.power, args.reset_aux)
        bus.start()
        reader = RC522(bus)
        run(args, reader)
        return 0
    except (HardwareError, OSError, ValueError, ImportError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Interrupted; any write in progress may be incomplete', file=sys.stderr)
        return 130
    finally:
        if reader:
            try:
                reader.stop()
            except Exception:
                pass
        if bus:
            try:
                bus.close()
            except Exception as error:
                print(f'Cleanup warning: {error}', file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())

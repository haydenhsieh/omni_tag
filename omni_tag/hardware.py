"""Legacy Bus Pirate SPI transport and MFRC522 ISO14443A operations."""
import time
from functools import reduce
from operator import xor


class HardwareError(RuntimeError):
    pass


def crc_a(data):
    crc = 0x6363
    for byte in data:
        byte ^= crc & 0xFF
        byte ^= (byte << 4) & 0xFF
        crc = ((crc >> 8) ^ (byte << 8) ^ (byte << 3) ^ (byte >> 4)) & 0xFFFF
    return crc.to_bytes(2, 'little')


class BusPirate:
    def __init__(self, serial_port, power=False, reset_aux=False):
        self.port = serial_port
        self.power = power
        self.reset_aux = reset_aux
        self.active = False

    def read(self, count):
        result = bytearray()
        while len(result) < count:
            part = self.port.read(count - len(result))
            if not part:
                raise HardwareError('Bus Pirate serial timeout')
            result.extend(part)
        return bytes(result)

    def ack(self, command):
        self.port.write(bytes([command]))
        if self.read(1) != b'\x01':
            raise HardwareError(f'Bus Pirate rejected command {command:02x}')

    def start(self):
        self.port.reset_input_buffer()
        # Stop as soon as BBIO1 arrives: extra zeros would queue extra banners.
        banner = bytearray()
        for _ in range(25):
            self.port.write(b'\0')
            banner.extend(self.port.read(5))
            if b'BBIO1' in banner:
                break
        else:
            raise HardwareError('No BBIO1 banner; legacy binary SPI firmware required')
        self.port.write(b'\x01')
        if self.read(4) != b'SPI1':
            raise HardwareError('Expected SPI1 banner')
        self.active = True
        self.ack(0x8A)  # driven 3.3V, CKP=0, CKE=1, SMP=0 (mode 0)
        self.ack(0x61)  # 125 kHz
        self.ack(0x49 if self.power else 0x41)  # CS high, pullups off
        if self.reset_aux:
            # AUX starts low above: hold NRSTPD low, then release at 3.3 V.
            time.sleep(0.01)
            self.ack(0x4B if self.power else 0x43)
        time.sleep(0.05)

    def transfer(self, data):
        self.ack(0x02)
        try:
            result = bytearray()
            for offset in range(0, len(data), 16):
                chunk = data[offset:offset + 16]
                self.ack(0x10 | (len(chunk) - 1))
                self.port.write(chunk)
                result.extend(self.read(len(chunk)))
            return bytes(result)
        finally:
            self.ack(0x03)

    def close(self):
        try:
            if self.active:
                self.ack(0x41)
                self.port.write(b'\x00')
                if self.read(5) != b'BBIO1':
                    raise HardwareError('Failed to leave SPI mode')
                self.port.write(b'\x0f')
        finally:
            self.port.close()


class RC522:
    def __init__(self, bus):
        self.bus = bus

    def write(self, reg, value):
        self.bus.transfer(bytes([(reg << 1) & 0x7E, value]))

    def read(self, reg):
        return self.bus.transfer(bytes([0x80 | ((reg << 1) & 0x7E), 0]))[1]

    def init(self):
        self.write(0x01, 0x0F)
        time.sleep(0.05)
        version = self.read(0x37)
        if version in (0, 255):
            raise HardwareError('RC522 not responding; check power, reset and SPI wiring')
        for reg, value in ((0x2A, 0x8D), (0x2B, 0x3E), (0x2C, 0),
                           (0x2D, 30), (0x15, 0x40), (0x11, 0x3D),
                           (0x12, 0), (0x13, 0)):
            self.write(reg, value)
        self.write(0x14, self.read(0x14) | 3)
        time.sleep(0.01)
        return version

    def exchange(self, data, bits=0, command=0x0C):
        self.write(0x01, 0)
        self.write(0x04, 0x7F)
        self.write(0x0A, 0x80)
        for value in data:
            self.write(0x09, value)
        self.write(0x0D, bits)
        self.write(0x01, command)
        if command == 0x0C:
            self.write(0x0D, bits | 0x80)
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                irq = self.read(0x04)
                if irq & (0x10 if command == 0x0E else 0x30):
                    break
                if irq & 1:
                    raise HardwareError('Tag timeout; place one supported tag on the antenna')
            else:
                raise HardwareError('RC522 command timeout')
            if self.read(0x06) & 0x1B:
                raise HardwareError('RF error or collision; use one stationary tag')
            size = self.read(0x0A)
            if size > 64:
                raise HardwareError('Invalid FIFO size')
            reply = bytes(self.read(0x09) for _ in range(size))
            last = self.read(0x0C) & 7
            return reply, (size * 8 if not last else (size - 1) * 8 + last)
        finally:
            self.write(0x0D, bits)
            self.write(0x01, 0)

    def frame(self, data):
        return self.exchange(data + crc_a(data))

    def select(self):
        self.write(0x08, self.read(0x08) & ~8)
        atqa, bits = self.exchange(b'\x52', bits=7)
        if bits != 16:
            raise HardwareError('Invalid ATQA')
        uid = bytearray()
        for level in (0x93, 0x95, 0x97):
            part, bits = self.exchange(bytes([level, 0x20]))
            if bits != 40 or reduce(xor, part, 0):
                raise HardwareError('Invalid anticollision response')
            sak, bits = self.frame(bytes([level, 0x70]) + part)
            if bits != 24 or crc_a(sak[:1]) != sak[1:]:
                raise HardwareError('Invalid SAK CRC')
            uid.extend(part[1:4] if part[0] == 0x88 else part[:4])
            if not sak[0] & 4:
                return bytes(uid), atqa, sak[0]
        raise HardwareError('Invalid UID cascade')

    def authenticate(self, block, key, uid, key_b=False):
        self.exchange(bytes([0x61 if key_b else 0x60, block]) + key + uid[-4:], command=0x0E)
        if not self.read(0x08) & 8:
            raise HardwareError('Authentication failed; check key and card type')

    def unlock(self):
        self.write(0x08, self.read(0x08) & ~8)
        try:
            self.frame(b'\x50\x00')
        except HardwareError as error:
            if 'Tag timeout' not in str(error):
                raise
        self.expect_ack(*self.exchange(b'\x40', bits=7))
        self.expect_ack(*self.exchange(b'\x43'))

    @staticmethod
    def expect_ack(reply, bits):
        if bits != 4 or reply != b'\x0a':
            raise HardwareError('Tag rejected command (expected four-bit ACK)')

    def read_block(self, block):
        reply, bits = self.frame(bytes([0x30, block]))
        if bits != 144 or crc_a(reply[:16]) != reply[16:]:
            raise HardwareError('Invalid block response or CRC')
        return reply[:16]

    def write_block(self, block, data):
        if len(data) != 16:
            raise ValueError('A block must contain 16 bytes')
        self.expect_ack(*self.frame(bytes([0xA0, block])))
        self.expect_ack(*self.frame(data))
        if self.read_block(block) != data:
            raise HardwareError('Write verification failed')

    def stop(self):
        self.write(0x08, self.read(0x08) & ~8)
        self.write(0x14, self.read(0x14) & ~3)

# omni-tag

Python CLI for a Bus Pirate connected over SPI to an MFRC522 (RC522) module.
Read ISO14443A UIDs, read/write MIFARE Classic data blocks using a known key,
and change four-byte UIDs on **Gen1A Chinese magic cards** supporting the
HALT → seven-bit `40` → `43` backdoor. “UID modifiable” alone does not identify
this generation. Gen2/CUID, Gen3, Gen4, Ultralight/NTAG UID writing, key recovery,
and full-card cloning are not implemented. Use cards you own or administer.

## Setup and usage

Requires Python 3.10+ and Bus Pirate firmware exposing `BBIO1` / `SPI1`
legacy binary SPI (primarily Bus Pirate v3/v4). Newer Bus Pirates have different
binary interfaces; this application does not configure their power supply or
select their binary mode. Only use them if their selected legacy interface and
pin mapping have been verified. The normal terminal interface is not supported.
Close serial terminals before running the CLI.

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e .
omni-tag --help
omni-tag --port /dev/ttyUSB0 --power info
omni-tag --port /dev/ttyUSB0 --power read-block 4
omni-tag --port /dev/ttyUSB0 --power read-block 4 --key A0A1A2A3A4A5 --key-type A
omni-tag --port /dev/ttyUSB0 --power read-block 0 --magic
omni-tag --port /dev/ttyUSB0 --power write-block 4 00112233445566778899AABBCCDDEEFF --yes
omni-tag --port /dev/ttyUSB0 --power set-uid DEADBEEF --yes
```

Omit `--power` when using an external regulated 3.3 V supply. Default serial
speed is 115200; `--baud` changes it. SPI uses mode 0, 125 kHz, driven 3.3 V
outputs, no pull-ups. Linux serial access may require your distribution's serial
device group. Windows ports such as `COM3` also work with pyserial.

Place exactly one stationary card close to the antenna before each command.
`info` outputs JSON (ATQA bytes in RF receive order); block reads output 32 hex
digits. The default authentication key is `FFFFFFFFFFFF`; no keys are guessed.
`--magic` bypasses normal authentication only on compatible Gen1A cards.
Block addresses are decimal or `0x` hexadecimal. Supported Classic capacities
are Mini, 1K and 4K, selected from SAK. Seven-byte UIDs can be read, but cannot
be changed by this tool.

Writes require `--yes` and are read back for verification. `write-block` refuses
block 0 and all sector trailers to protect manufacturer data, keys and access
bits. `set-uid` reads block 0 first, replaces UID and its XOR BCC, preserves the
other eleven bytes, verifies block 0, cycles the RF field, and verifies the UID
through anticollision. Save `read-block 0 --magic` output before changing a UID.
Do not remove the card or power during a write; verification failures do not
imply that the write was rolled back. Exit codes: 0 success, 1 hardware/I/O
failure, 2 invalid arguments, 130 interruption.

## Linux udev access

[udev/70-buspirate.rules](udev/70-buspirate.rules) grants the active local
login session serial access through systemd-logind (`uaccess`), tells
ModemManager to ignore matching ports, and creates `/dev/buspirate-<serial>`
symlinks. It covers the v3 FTDI ID `0403:6001` and v4 ID `04d8:fb00`
([USB ID reference](https://sigrok.org/wiki/Dangerous_Prototypes_Buspirate/Info)).
The v3 ID is shared by other FTDI adapters: for a device-specific rule, inspect
the serial number and add `ATTRS{serial}=="YOUR_SERIAL",` to the matching rule
before installing it:

```sh
udevadm info --attribute-walk --name=/dev/ttyUSB0
sudo install -m 0644 udev/70-buspirate.rules /etc/udev/rules.d/70-buspirate.rules
sudo udevadm control --reload-rules
```

Unplug and reconnect the Bus Pirate, then find its symlink and use it as the
CLI port:

```sh
ls -l /dev/buspirate-*
omni-tag --port /dev/buspirate-YOUR_SERIAL --power info
```

Use `/dev/ttyACM0` instead of `/dev/ttyUSB0` when inspecting a v4, adjusting the
number to your device. If a device has no unique serial, use its
`/dev/serial/by-path/` link instead. These rules do not cover newer Bus Pirates
or bootloader devices. For SSH, headless services, or systems without
systemd-logind, use your distribution's serial group (`dialout` on Debian/Ubuntu,
`uucp` on Arch), add your user to that group and log in again. `uaccess` grants
access to the active local session only. The file is provided in the repository;
installing the Python package does not install system rules.

## Wiring guide

Disconnect power before wiring. Use the **signal labels** on your Bus Pirate,
not cable colors: cable pin orders/colors differ. These are the classic Bus
Pirate v3/v4 signal names. RC522 boards must be configured for SPI (typical
inexpensive eight-pin modules already are).

| Bus Pirate / supply | RC522 module | Purpose |
| --- | --- | --- |
| 3.3 V output, or external regulated 3.3 V | 3.3V | Power |
| GND | GND | Common ground (also connect external supply ground) |
| CLK | SCK | SPI clock |
| MOSI | MOSI | Host to reader |
| MISO | MISO | Reader to host |
| CS | SDA / SS / NSS | Active-low SPI chip select; **not I²C SDA** |
| AUX (with `--reset-aux`), or 3.3 V | RST / NRSTPD | Separate reset control, or hold reset high |
| No connection | IRQ | Polling is used |

Never connect RC522 power or logic to 5 V. Use one power source; do not tie an
external supply output to the Bus Pirate supply output. With external power,
leave the Bus Pirate 3.3 V output disconnected and omit `--power`. On legacy
Bus Pirates `--power` enables the onboard supplies; only wire the 3.3 V output.
Keep jumpers short. An unstable or overloaded supply causes intermittent reads;
use a suitable external 3.3 V supply if the reader load exceeds your board's
available current. RST must not float. To keep power and reset on separate Bus Pirate pins,
connect **3.3 V → RC522 3.3V** and **AUX → RC522 RST**, then run:

```sh
omni-tag --port /dev/ttyUSB0 --power --reset-aux info
```

Use `--reset-aux` on every command with this wiring. It holds AUX low for
10 ms at startup, drives it high at 3.3 V, and waits 50 ms before reader
initialization. AUX remains high during operation and is driven low during
cleanup. Without this option AUX stays low, so an AUX-wired reader remains in
reset. The option also works with an external 3.3 V supply (omit `--power`).
Keep VPU disconnected; it is not a reset-control output.

If reader detection fails, check ground, 3.3 V, RST high and SDA/CS wiring.
A tag timeout can mean no card, an unsupported tag or inadequate RF power.
A backdoor ACK failure usually means an incompatible magic-card generation.
The CLI releases Crypto1, switches off the antenna and exits binary mode on
normal completion; legacy onboard power is disabled during cleanup.

## Verification and references

```sh
python -m unittest discover -s tests -v
```

Tests use simulated transports/readers; physical Bus Pirate, RF timing and
card compatibility still need validation on your hardware.

Protocol references:
- [Bus Pirate legacy binary SPI](https://docs.buspirate.com/docs/binmode-reference/protocol-spi-legacy/)
- [NXP MFRC522 datasheet](https://www.nxp.com/docs/en/data-sheet/MFRC522.pdf)
- [libnfc MIFARE Classic utility and magic unlock implementation](https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-mfclassic.c)

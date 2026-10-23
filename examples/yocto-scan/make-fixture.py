#!/usr/bin/env python3
"""Builds a small, realistic Yocto deploy directory for testing 'emb3d-wb scan'.
It is synthetic: alarm-hub-image, the hub of the surveillance and alarm system example
(examples/system), on raspberrypi4-64 (Compute Module 4 class) with poky scarthgap:
RAUC + hawkBit updates, a Mosquitto event bus with TLS, GStreamer RTSP recording of the
cameras, ModemManager for the LTE backup path to the alarm receiving centre, an installer web
interface (lighttpd, TLS), key-only OpenSSH and a serial console. Run: python3 make-fixture.py"""
import io, json, os, tarfile, time

IMG = 'alarm-hub-image-raspberrypi4-64'
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'deploy')
os.makedirs(D, exist_ok=True)

testdata = {
    'MACHINE': 'raspberrypi4-64', 'SOC_FAMILY': 'rpi', 'MACHINEOVERRIDES': 'aarch64:armv8a:rpi:raspberrypi4-64',
    'MACHINE_FEATURES': 'apm usbhost keyboard vfat ext2 screen touchscreen alsa bluetooth wifi sdio vc4graphics',
    'DISTRO': 'poky', 'DISTRO_VERSION': '5.0.4', 'DISTRO_CODENAME': 'scarthgap',
    'DISTRO_FEATURES': 'acl alsa bluetooth ipv6 usbhost wifi xattr pam systemd usrmerge rauc',
    'IMAGE_BASENAME': 'alarm-hub-image', 'PN': 'alarm-hub-image',
    'IMAGE_FEATURES': 'ssh-server-openssh package-management',
    'IMAGE_FSTYPES': 'tar.gz wic.bz2 wic.bmap',
    'SERIAL_CONSOLES': '115200;ttyS0',
    'PREFERRED_PROVIDER_virtual/kernel': 'linux-raspberrypi',
    'PREFERRED_PROVIDER_virtual/bootloader': 'u-boot',
    'UBOOT_SIGN_ENABLE': '1', 'UBOOT_SIGN_KEYNAME': 'alarm-hub-fit',
    'TUNE_FEATURES': 'aarch64 crc cortexa72',
    'RAUC_BUNDLE_FORMAT': 'verity',
    'BUILDNAME': '20261015120000',
}
json.dump(testdata, open(os.path.join(D, IMG + '.rootfs.testdata.json'), 'w'), indent=2)

pkgs = [('base-files', '3.0.14-r0'), ('busybox', '1.36.1-r0'), ('openssh-sshd', '9.6p1-r0'), ('openssh-ssh', '9.6p1-r0'),
        ('openssh-keygen', '9.6p1-r0'), ('rauc', '1.11.3-r0'), ('rauc-hawkbit-updater', '1.3-r0'), ('mosquitto', '2.0.18-r0'),
        ('kernel-image-image-6.6.22-v8', '1:6.6.22+git-r0'), ('kernel-module-brcmfmac-6.6.22-v8', '1:6.6.22+git-r0'),
        ('systemd', '1:255.4-r0'), ('libssl3', '3.2.1-r0'), ('ca-certificates', '20240203-r0'), ('u-boot-env', '2024.01-r0'),
        ('modemmanager', '1.22.0-r0'), ('libqmi', '1.34.0-r0'), ('gstreamer1.0', '1.22.12-r0'),
        ('libgstrtspserver-1.0-0', '1.22.12-r0'), ('alsa-lib', '1.2.11-r0'), ('lighttpd', '1.4.75-r0'),
        ('alarm-hub-daemon', '1.4.0-r0')]
with open(os.path.join(D, IMG + '.rootfs.manifest'), 'w') as f:
    for n, v in pkgs:
        f.write(f'{n} cortexa72 {v}\n')

files = {
    'etc/passwd': 'root:x:0:0:root:/home/root:/bin/sh\nmosquitto:x:998:998::/var/lib/mosquitto:/bin/false\nsshd:x:997:997::/var/run/sshd:/bin/false\nwww:x:996:996::/var/www:/bin/false\nalarm:x:995:995::/var/lib/alarm-hub:/bin/false\n',
    'etc/shadow': 'root:*:19000:0:99999:7:::\nmosquitto:!:19000::::::\n',
    'etc/ssh/sshd_config': 'Port 22\nPermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n',
    'etc/rauc/system.conf': '[system]\ncompatible=alarm-hub-rpi4\nbootloader=uboot\n\n[keyring]\npath=/etc/rauc/ca.cert.pem\n\n[slot.rootfs.0]\ndevice=/dev/mmcblk0p2\ntype=ext4\nbootname=A\n',
    'etc/rauc-hawkbit-updater/config.conf': '[client]\nhawkbit_server = updates.example.com\nssl = true\n',
    'etc/mosquitto/mosquitto.conf': 'listener 8883\ncertfile /etc/mosquitto/certs/server.crt\nkeyfile /etc/mosquitto/certs/server.key\npassword_file /etc/mosquitto/passwd\nallow_anonymous false\n',
    'etc/systemd/journald.conf': '[Journal]\nStorage=volatile\n',
    'etc/lighttpd.conf': 'server.port = 443\nssl.engine = "enable"\nssl.pemfile = "/etc/lighttpd/installer.pem"\nserver.document-root = "/www/installer"\n',
    'etc/alarm-hub/arc.conf': '# Alarm receiving centre: SIA DC-09, AES-128, primary over Ethernet, backup over LTE\nprimary = arc.example.com:9000\nbackup = arc-backup.example.com:9000\nencryption = aes128\nsupervision = 90\n',
}
tar_path = os.path.join(D, IMG + '.rootfs.tar.gz')
with tarfile.open(tar_path, 'w:gz') as t:
    def add(name, data=None, link=None):
        ti = tarfile.TarInfo('./' + name); ti.mtime = 1760500000
        if link: ti.type = tarfile.SYMTYPE; ti.linkname = link; t.addfile(ti)
        else: b = data.encode(); ti.size = len(b); t.addfile(ti, io.BytesIO(b))
    for n, c in files.items(): add(n, c)
    add('etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service', link='/usr/lib/systemd/system/serial-getty@.service')

with open(os.path.join(D, 'config-raspberrypi4-64'), 'w') as f:
    f.write('CONFIG_MMU=y\nCONFIG_MODULES=y\nCONFIG_MODULE_SIG=y\n# CONFIG_MODULE_SIG_FORCE is not set\nCONFIG_USB_SUPPORT=y\n# CONFIG_TCG_TPM is not set\n# CONFIG_CAN is not set\nCONFIG_STRICT_KERNEL_RWX=y\n')

def bom(subject, comps, vulns):
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'timestamp': '2026-10-15T12:00:00Z', 'component': {'type': 'operating-system' if 'image' in subject[0] else 'firmware', 'name': subject[0], 'version': subject[1]}},
            'components': [{'type': 'library', 'bom-ref': f'{n}@{v}', 'name': n, 'version': v, 'purl': f'pkg:yocto/{n}@{v}', 'cpe': c} for n, v, c in comps],
            'vulnerabilities': vulns}

rootfs_bom = bom(('alarm-hub-image', '5.0.4'), [
    ('openssh', '9.6p1', 'cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*'),
    ('mosquitto', '2.0.18', 'cpe:2.3:a:eclipse:mosquitto:2.0.18:*:*:*:*:*:*:*'),
    ('rauc', '1.11.3', 'cpe:2.3:a:pengutronix:rauc:1.11.3:*:*:*:*:*:*:*'),
    ('rauc-hawkbit-updater', '1.3', None),
    ('busybox', '1.36.1', 'cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*'),
    ('linux-raspberrypi', '6.6.22', 'cpe:2.3:o:linux:linux_kernel:6.6.22:*:*:*:*:*:*:*'),
    ('systemd', '255.4', 'cpe:2.3:a:systemd_project:systemd:255.4:*:*:*:*:*:*:*'),
    ('openssl', '3.2.1', 'cpe:2.3:a:openssl:openssl:3.2.1:*:*:*:*:*:*:*'),
    ('modemmanager', '1.22.0', None),
    ('gstreamer1.0', '1.22.12', 'cpe:2.3:a:gstreamer_project:gstreamer:1.22.12:*:*:*:*:*:*:*'),
    ('gstreamer1.0-rtsp-server', '1.22.12', None),
    ('alsa-lib', '1.2.11', None),
    ('lighttpd', '1.4.75', 'cpe:2.3:a:lighttpd:lighttpd:1.4.75:*:*:*:*:*:*:*'),
    ('alarm-hub-daemon', '1.4.0', None),
], [
    {'id': 'CVE-2024-6387', 'source': {'name': 'NVD'}, 'affects': [{'ref': 'openssh@9.6p1'}]},
    {'id': 'CVE-2023-48795', 'source': {'name': 'NVD'}, 'affects': [{'ref': 'openssh@9.6p1'}], 'analysis': {'state': 'not_affected', 'justification': 'code_not_reachable'}},
    {'id': 'CVE-2024-3935', 'source': {'name': 'NVD'}, 'affects': [{'ref': 'mosquitto@2.0.18'}]},
    {'id': 'CVE-2024-2511', 'source': {'name': 'NVD'}, 'affects': [{'ref': 'openssl@3.2.1'}], 'analysis': {'state': 'resolved'}},
])
json.dump(rootfs_bom, open(os.path.join(D, IMG + '.rootfs.cdx.json'), 'w'), indent=2)
uboot_bom = bom(('u-boot-raspberrypi4-64', '2024.01'), [('u-boot', '2024.01', 'cpe:2.3:a:denx:u-boot:2024.01:*:*:*:*:*:*:*')],
                [{'id': 'CVE-2024-57256', 'source': {'name': 'NVD'}, 'affects': [{'ref': 'u-boot@2024.01'}]}])
json.dump(uboot_bom, open(os.path.join(D, 'u-boot-raspberrypi4-64.cdx.json'), 'w'), indent=2)
print('fixture written to', D)

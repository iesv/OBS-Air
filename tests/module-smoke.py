"""Load the built plugin into the real OBS 32 library and inspect its API."""
from pathlib import Path
import ctypes as c
import hashlib
import os
import plistlib
import re
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(r"project\(OBS-Air VERSION ([0-9.]+)", (ROOT / "CMakeLists.txt").read_text())[1]
PTR = c.c_void_p
STR = c.c_char_p


def process_resources():
    """Return peak resident bytes and open handles or descriptors."""
    if sys.platform == "win32":
        class Memory(c.Structure):
            _fields_ = [("cb", c.c_uint32), ("faults", c.c_uint32)] + [
                (name, c.c_size_t) for name in ("peak_rss", "rss", "peak_paged", "paged",
                    "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]
        current = c.windll.kernel32.GetCurrentProcess
        current.restype = PTR
        memory = Memory()
        memory.cb = c.sizeof(memory)
        query = c.windll.psapi.GetProcessMemoryInfo
        query.argtypes = [PTR, c.POINTER(Memory), c.c_uint32]
        assert query(current(), c.byref(memory), memory.cb)
        handles = c.c_uint32()
        count = c.windll.kernel32.GetProcessHandleCount
        count.argtypes = [PTR, c.POINTER(c.c_uint32)]
        assert count(current(), c.byref(handles))
        return memory.peak_rss, handles.value
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, len(os.listdir("/dev/fd"))


def digest(password, nonce):
    md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
    proof = md5(f'{md5("iPhone:raop:" + password)}:{nonce}:{md5("SETUP:/test")}')
    return (f'Authorization: Digest username="iPhone", realm="raop", nonce="{nonce}", '
            f'uri="/test", response="{proof}"\r\n').encode()


def check_windows_installer(package):
    installer = (package.parents[2] / "install_obs-air.bat").read_bytes().decode("ascii")
    finish = installer.split(":finish\r\n", 1)[1]
    assert 'timeout.exe" /t 5 /nobreak' in finish
    with tempfile.TemporaryDirectory(prefix="obs-air-countdown-") as directory:
        script = Path(directory) / "countdown.bat"
        console_test = Path(directory) / "console.py"
        transcript = Path(directory) / "countdown.txt"
        script.write_bytes(('@echo off\r\nset "install_result=0"\r\n' + finish).encode("ascii"))
        console_test.write_text(
            'import subprocess, sys\n'
            'with open("CONIN$", "r+b", buffering=0) as console, open(sys.argv[2], "wb") as output:\n'
            '    subprocess.run(["cmd.exe", "/d", "/c", sys.argv[1]], stdin=console, '
            'stdout=output, stderr=subprocess.STDOUT, check=True)\n', encoding="ascii")
        startup = subprocess.STARTUPINFO()
        startup.dwFlags = subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = subprocess.SW_HIDE
        started = time.monotonic()
        # TIMEOUT needs console input; keep the test console hidden.
        subprocess.run([sys.executable, str(console_test), str(script), str(transcript)],
                       startupinfo=startup, creationflags=subprocess.CREATE_NEW_CONSOLE, check=True, timeout=20)
        assert time.monotonic() - started >= 4
        text = transcript.read_bytes()
        assert b"5" in text and b"\b0" in text and b"ERROR" not in text
    print("Windows installer success countdown and automatic exit PASS")


def check_macos_installer(stage, home):
    environment = {**os.environ, "HOME": home}
    subprocess.run(["xattr", "-w", "com.apple.quarantine", "0083;00000000;OBS-Air test;",
                    str(stage / "obs-air.plugin")], check=True)
    started = time.monotonic()
    result = subprocess.run(["bash", str(stage / "install_obs-air.sh")],
                            input="\n", text=True, env=environment, check=True, capture_output=True)
    assert time.monotonic() - started >= 5
    assert all(f"Closing in {seconds}s..." in result.stdout for seconds in range(5, 0, -1))
    bundle = Path(home) / "Library/Application Support/obs-studio/plugins/obs-air.plugin"
    assert "com.apple.quarantine" not in subprocess.check_output(["xattr", "-r", str(bundle)], text=True)
    return bundle


def main():
    if sys.platform == "win32":
        runtime = ROOT / ".deps/obs-runtime/bin/64bit"
        package = ROOT / f"build/package/_CPack_Packages/win64/ZIP/OBS-Air-{VERSION}-windows-x64/obs-studio/plugins/obs-air"
        plugin_path = package / "bin/64bit/obs-air.dll"
        data_path = package / "data"
        check_windows_installer(package)
        handles = [os.add_dll_directory(str(runtime)), os.add_dll_directory(str(plugin_path.parent))]
        os.chdir(runtime)
        c.windll.kernel32.SetDllDirectoryW(str(plugin_path.parent))
        obs = c.CDLL(str(runtime / "obs.dll"))
    else:
        frameworks = ROOT / ".deps/obs-runtime/OBS.app/Contents/Frameworks"
        stage = ROOT / f"build/package/OBS-Air-{VERSION}-macos-arm64"
        installation = tempfile.TemporaryDirectory(prefix="obs-air-install-")
        bundle = check_macos_installer(stage, installation.name)
        plugin_path = bundle / "Contents/MacOS/obs-air"
        data_path = plugin_path.parents[1] / "Resources"
        # Resolve host-provided QtCore explicitly, without a GUI application.
        qt = c.CDLL(str(frameworks / "QtCore.framework/Versions/A/QtCore"), mode=c.RTLD_GLOBAL)
        obs = c.CDLL(str(frameworks / "libobs.framework/Versions/A/libobs"), mode=c.RTLD_GLOBAL)
    plugin = c.CDLL(str(plugin_path))

    def api(name, result, arguments):
        function = getattr(obs, name)
        function.restype, function.argtypes = result, arguments
        return function

    assert api("obs_startup", c.c_bool, [STR, STR, PTR])(b"zh-TW", None, None)
    module = PTR()
    assert api("obs_open_module", c.c_int, [c.POINTER(PTR), STR, STR])(
        c.byref(module), str(plugin_path).encode(), str(data_path).encode()) == 0
    assert api("obs_init_module", c.c_bool, [PTR])(module)
    get_name = api("obs_source_get_display_name", STR, [STR])
    get_properties = api("obs_get_source_properties", PTR, [STR])
    get_property = api("obs_properties_get", PTR, [PTR, STR])
    description = api("obs_property_description", STR, [PTR])
    destroy = api("obs_properties_destroy", None, [PTR])
    plugin.obs_module_set_locale.argtypes = [STR]
    plugin.obs_module_author.restype = STR
    assert plugin.obs_module_author() == b"haliluya.net"
    for locale, expected, restart_label in (
        (b"en-US", "Enable receiver", "Restart receiver"),
        (b"zh-CN", "\u542f\u7528\u63a5\u6536\u5668", "\u91cd\u542f\u63a5\u6536\u5668"),
        (b"zh-TW", "\u555f\u7528\u63a5\u6536\u5668", "\u91cd\u555f\u63a5\u6536\u5668"),
    ):
        plugin.obs_module_set_locale(locale)
        assert get_name(b"obs_air_source") == b"AirPlay (OBS-Air)"
        properties = get_properties(b"obs_air_source")
        assert properties
        assert api("obs_properties_get_flags", c.c_uint32, [PTR])(properties) & 1
        assert description(get_property(properties, b"enabled")).decode() == expected
        metadata = description(get_property(properties, b"plugin_info"))
        assert VERSION.encode() in metadata and b"haliluya.net" in metadata
        assert b'align="right"' in metadata and b'<a href="https://haliluya.net/">haliluya.net</a>' in metadata
        assert not get_property(properties, b"version") and not get_property(properties, b"author")
        assert api("obs_property_text_type", c.c_int, [PTR])(get_property(properties, b"password")) == 0
        assert get_property(properties, b"block_takeover") and get_property(properties, b"restart")
        assert get_property(properties, b"follow_volume")
        assert description(get_property(properties, b"restart")).decode() == restart_label
        destroy(properties)
        print("Real OBS 32 module load, locale and settings metadata PASS:", locale.decode())
    plugin.obs_module_set_locale(b"en-US")
    create_data = api("obs_data_create", PTR, [])
    release_data = api("obs_data_release", None, [PTR])
    set_string = api("obs_data_set_string", None, [PTR, STR, STR])
    get_string = api("obs_data_get_string", STR, [PTR, STR])
    set_integer = api("obs_data_set_int", None, [PTR, STR, c.c_longlong])
    create_source = api("obs_source_create", PTR, [STR, STR, PTR, PTR])
    release_source = api("obs_source_release", None, [PTR])
    set_bool = api("obs_data_set_bool", None, [PTR, STR, c.c_bool])
    task_type = c.CFUNCTYPE(None, PTR)
    barrier = task_type(lambda _: None)
    queue_task = api("obs_queue_task", None, [c.c_int, task_type, PTR, c.c_bool])

    def wait_destroy():
        queue_task(3, barrier, None, True)  # OBS_TASK_DESTROY works without a graphics/audio thread.
    source_properties = api("obs_source_properties", PTR, [PTR])

    def source_status(source):
        properties = source_properties(source)
        text = description(get_property(properties, b"status"))
        assert not get_property(properties, b"address")
        assert not get_property(properties, b"connection_info")
        assert b"IP:" in text and " · ".encode() in text
        assert not api("obs_property_text_info_word_wrap", c.c_bool, [PTR])(get_property(properties, b"status"))
        destroy(properties)
        status = re.sub(rb"<[^>]+>", b"", text).split(b"&nbsp;&nbsp;|&nbsp;&nbsp;", 1)[0]
        return status.split(" · ".encode(), 1)[1]

    def request(client, method, path, body=b"", headers=b""):
        client.sendall(f"{method} {path} RTSP/1.0\r\nCSeq: 1\r\nContent-Length: {len(body)}\r\n".encode()
                       + headers + b"\r\n" + body)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = client.recv(4096)
            assert chunk
            response += chunk
        header, data = response.split(b"\r\n\r\n", 1)
        length = re.search(rb"Content-Length: (\d+)", header)
        size = int(length[1]) if length else 0
        while len(data) < size:
            chunk = client.recv(4096)
            assert chunk
            data += chunk
        return header, data[:size]

    def connect_device(name, port=7800, password=None):
        client = socket.create_connection(("127.0.0.1", port), timeout=3)
        assert b"200 OK" in request(client, "POST", "/fp-setup", bytes(4) + b"\x03" + bytes(159))[0]
        body = plistlib.dumps({"deviceID": "02:11:22:33:44:55", "name": name, "model": "iPhone",
                              "eiv": bytes(16), "ekey": bytes(72), "timingProtocol": "NTP", "timingPort": 9},
                             fmt=plistlib.FMT_BINARY)
        header = request(client, "SETUP", "/test", body)[0]
        if password is not None and b"401 Unauthorized" in header:
            nonce = re.search(rb'nonce="([^"]+)"', header)[1].decode()
            header = request(client, "SETUP", "/test", body, digest(password, nonce))[0]
        return client, header

    def restart(source):
        properties = source_properties(source)
        api("obs_property_button_clicked", c.c_bool, [PTR, PTR])(get_property(properties, b"restart"), None)
        destroy(properties)

    def wait_for(check):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.01)
        assert check()

    enum_hotkey_type = c.CFUNCTYPE(c.c_bool, PTR, c.c_size_t, PTR)
    hotkey_name = api("obs_hotkey_get_name", STR, [PTR])

    def restart_keys():
        keys = []
        @enum_hotkey_type
        def collect(_, identity, key):
            if hotkey_name(key) == b"OBS-Air.Restart":
                keys.append(identity)
            return True
        api("obs_enum_hotkeys", None, [enum_hotkey_type, PTR])(collect, None)
        return keys

    api("obs_hotkey_enable_callback_rerouting", None, [c.c_bool])(True)
    trigger_key = api("obs_hotkey_trigger_routed_callback", None, [c.c_size_t, c.c_bool])

    def check_password_input():
        # Exercise the actual OBS field callback: normal characters never refresh
        # the widget, while pasted non-ASCII/whitespace is removed immediately.
        properties = get_properties(b"obs_air_source")
        password_field = get_property(properties, b"password")
        modify = api("obs_property_modified", c.c_bool, [PTR, PTR])
        editing = create_data()
        for value in (b"", b"Ab12", b"Ab12_!@#-", bytes(range(0x21, 0x7f))):
            set_string(editing, b"password", value)
            assert not modify(password_field, editing) and get_string(editing, b"password") == value
        for value, expected in (("Ab12\u4e2d\u6587_!", b"Ab12_!"), ("\u4e2d\u6587\U0001f512\u3000 \t\n", b""), ("\uff21\uff22\uff11\uff12 Ab12", b"Ab12")):
            set_string(editing, b"password", value.encode())
            assert modify(password_field, editing) and get_string(editing, b"password") == expected
        release_data(editing)
        destroy(properties)
        print("Native password input filtering and normal typing without widget refresh PASS")

    check_password_input()

    def receiver_info():
        with socket.create_connection(("127.0.0.1", 7800), timeout=3) as client:
            header, body = request(client, "GET", "/info")
            assert b"200 OK" in header, "receiver metadata request failed"
            return plistlib.loads(body)

    settings = create_data()
    def check_restart(settings):
        primary = create_source(b"obs_air_source", b"OBS-Air smoke primary", settings, None)
        assert primary and source_status(primary) == b"Waiting for an AirPlay device"
        assert not receiver_info()["features"] & (1 << 27)
        saved = api("obs_source_get_settings", PTR, [PTR])(primary)
        assert api("obs_data_get_int", c.c_longlong, [PTR, STR])(saved, b"port") == 7800
        assert api("obs_data_get_string", STR, [PTR, STR])(saved, b"password") == b""
        assert api("obs_data_get_bool", c.c_bool, [PTR, STR])(saved, b"block_takeover")
        assert not api("obs_data_get_bool", c.c_bool, [PTR, STR])(saved, b"follow_volume")
        release_data(saved)
        # Pending edits do not affect the restart button's applied configuration.
        set_string(settings, b"password", b"unapplied")
        restart(primary)
        first, header = connect_device("Primary <iPhone>")
        assert b"200 OK" in header
        properties = source_properties(primary)
        assert b"Primary &lt;iPhone&gt;" in description(get_property(properties, b"status"))
        destroy(properties)
        keys = restart_keys()
        assert len(keys) == 1
        trigger_key(keys[0], False)
        assert b"200 OK" in request(first, "OPTIONS", "*")[0]
        trigger_key(keys[0], True)
        try:
            assert not first.recv(1)
        except ConnectionResetError:
            pass
        first.close()
        assert source_status(primary) == b"Waiting for an AirPlay device"
        release_source(primary)
        wait_destroy()
        assert not restart_keys()
        print("Native restart hotkey registration, key-up, disconnect and destruction PASS")

    check_restart(settings)

    def check_audio(settings):
        # Exercise audio-only and mirror sessions through the real protocol callbacks.
        set_bool(settings, b"follow_volume", True)
        set_string(settings, b"password", b"")
        primary = create_source(b"obs_air_source", b"OBS-Air smoke audio", settings, None)
        api("obs_source_set_volume", None, [PTR, c.c_float])(primary, 0.35)
        first, header = connect_device("Audio iPhone")
        assert b"200 OK" in header
        stream = {"type": 96, "ct": 4, "usingScreen": False, "spf": 1024}
        assert b"200 OK" in request(first, "SETUP", "/test", plistlib.dumps({"streams": [stream]}, fmt=plistlib.FMT_BINARY))[0]
        wait_for(lambda: source_status(primary) == b"Audio streaming")
        properties = source_properties(primary)
        assert b"Audio iPhone" in description(get_property(properties, b"status"))
        assert b"Video:" not in description(get_property(properties, b"status"))
        destroy(properties)
        for locale, state in ((b"zh-CN", "\u97f3\u9891\u6295\u653e"), (b"zh-TW", "\u97f3\u8a0a\u6295\u653e")):
            plugin.obs_module_set_locale(locale)
            properties = source_properties(primary)
            assert state.encode() in description(get_property(properties, b"status"))
            destroy(properties)
        plugin.obs_module_set_locale(b"en-US")

        def device_volume():
            header, body = request(first, "GET_PARAMETER", "/test", b"volume\r\n",
                                   b"Content-Type: text/parameters\r\n")
            assert b"200 OK" in header
            return float(body.split(b":", 1)[1])

        for volume, expected in ((-6.0, -6.0), (-30.0, -144.0), (-144.0, -144.0), (4.0, 0.0), (-10.0, -10.0)):
            assert b"200 OK" in request(first, "SET_PARAMETER", "/test", f"volume: {volume}\r\n".encode(),
                                        b"Content-Type: text/parameters\r\n")[0]
            wait_for(lambda: abs(device_volume() - expected) < 0.0001)
        assert abs(api("obs_source_get_volume", c.c_float, [PTR])(primary) - 0.35) < 0.00001
        assert b"200 OK" in request(first, "SETUP", "/test", plistlib.dumps(
            {"streams": [{"type": 110, "streamConnectionID": 1}]}, fmt=plistlib.FMT_BINARY))[0]
        wait_for(lambda: source_status(primary) == b"Connected")
        restart(primary)
        first.close()
        release_source(primary)
        wait_destroy()
        set_bool(settings, b"follow_volume", False)
        primary = create_source(b"obs_air_source", b"OBS-Air smoke fixed volume", settings, None)
        first, header = connect_device("Fixed volume iPhone")
        assert b"200 OK" in header
        assert b"200 OK" in request(first, "SETUP", "/test", plistlib.dumps({"streams": [stream]}, fmt=plistlib.FMT_BINARY))[0]
        wait_for(lambda: source_status(primary) == b"Audio streaming")
        assert b"200 OK" in request(first, "SET_PARAMETER", "/test", b"volume: -144\r\n",
                                    b"Content-Type: text/parameters\r\n")[0]
        assert device_volume() == 0.0
        assert b"200 OK" in request(first, "TEARDOWN", "/test", plistlib.dumps(
            {"streams": [{"type": 96}]}, fmt=plistlib.FMT_BINARY))[0]
        wait_for(lambda: source_status(primary) != b"Audio streaming")
        restart(primary)
        first.close()
        release_source(primary)
        wait_destroy()
        print("Native audio-only/mirror status, device volume/mute, independent mixer and teardown PASS")

    check_audio(settings)

    def check_connections(settings):
        set_string(settings, b"password", b"")
        set_bool(settings, b"block_takeover", True)
        primary = create_source(b"obs_air_source", b"OBS-Air smoke protected", settings, None)
        first, header = connect_device("Protected iPhone")
        assert b"200 OK" in header
        challenger, header = connect_device("Other iPhone")
        assert b"409" in header and b"200 OK" in request(first, "OPTIONS", "*")[0]
        properties = source_properties(primary)
        assert b"Protected iPhone" in description(get_property(properties, b"status"))
        destroy(properties)
        challenger.close()
        restart(primary)
        first.close()
        print("Native receiver restart, pending edits, device identity and takeover protection PASS")
        # Report exact media ports and reject SETUP when a socket cannot start.
        for protocol, port in (("UDP", 7811), ("TCP", 7900), ("UDP", 7812), ("UDP", 7813)):
            with socket.socket(type=socket.SOCK_STREAM if protocol == "TCP" else socket.SOCK_DGRAM) as occupied:
                if sys.platform == "win32":
                    occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                occupied.bind(("0.0.0.0", port))
                if protocol == "TCP":
                    occupied.listen()
                client, header = connect_device("Port test")
                if port != 7811:
                    assert b"200 OK" in header
                    stream = {"type": 110, "streamConnectionID": 1} if protocol == "TCP" else {"type": 96, "ct": 4}
                    header = request(client, "SETUP", "/test", plistlib.dumps({"streams": [stream]}, fmt=plistlib.FMT_BINARY))[0]
                assert b"503" in header and f"Cannot bind {protocol} {port}".encode() in source_status(primary)
                client.close()
            restart(primary)
        print("TCP mirror and UDP timing/control/data port diagnostics PASS")
        second = create_source(b"obs_air_source", b"OBS-Air smoke duplicate", settings, None)
        assert second and b"Another OBS-Air receiver is running" in source_status(second)
        release_source(second)
        release_source(primary)
        wait_destroy()
        # Imported settings must fail closed rather than silently disabling access
        # control; then validate fixed password and clearing it on receiver restarts.
        for value in ("\u4e2d\u6587", "secret pass", "pass\U0001f512", "Valid_123!", ""):
            set_string(settings, b"password", value.encode())
            source = create_source(b"obs_air_source", b"OBS-Air smoke password", settings, None)
            if value in ("Valid_123!", ""):
                assert source_status(source) == b"Waiting for an AirPlay device"
                assert not receiver_info()["features"] & (1 << 27)
            else:
                assert b"Invalid connection password" in source_status(source)
                saved = api("obs_source_get_settings", PTR, [PTR])(source)
                assert get_string(saved, b"password") == value.encode()
                release_data(saved)
                restart(source)
                assert b"Invalid connection password" in source_status(source)
            release_source(source)
            wait_destroy()
        print("Legacy PIN advertisement disabled, invalid password rejection and cleared password restart PASS")
        # Verify an occupied base port is reported without affecting its owner.
        while True:
            occupied = socket.socket()
            if sys.platform == "win32":
                occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            occupied.bind(("0.0.0.0", 0))
            if occupied.getsockname()[1] <= 65000:
                break
            occupied.close()
        with occupied:
            occupied.listen()
            set_integer(settings, b"port", occupied.getsockname()[1])
            conflict = create_source(b"obs_air_source", b"OBS-Air smoke conflict", settings, None)
            assert f"Cannot bind TCP {occupied.getsockname()[1]}".encode() in source_status(conflict)
            release_source(conflict)
            wait_destroy()

    check_connections(settings)

    def check_stress(settings):
        began = last_report = time.monotonic()
        cpu_began = time.process_time()
        cycle = 0
        baseline = None
        mirror = {"type": 110, "streamConnectionID": 1}
        audio = {"type": 96, "ct": 4, "usingScreen": False}
        while time.monotonic() - began < 600 or cycle < 20:
            port = 7800 if cycle % 2 else 8100
            password = "Stress_123!" if cycle % 2 else ""
            set_integer(settings, b"port", port)
            set_string(settings, b"password", password.encode())
            # Recreate after applying settings; video updates need OBS's render loop.
            primary = create_source(b"obs_air_source", b"OBS-Air stress", settings, None)
            wait_for(lambda: source_status(primary) == b"Waiting for an AirPlay device")
            first, header = connect_device("Stress iPhone", port, password)
            assert b"200 OK" in header
            # Repeated pairing must release keys and preserve the active owner.
            with socket.create_connection(("127.0.0.1", port), timeout=3) as pairing:
                header, public_key = request(pairing, "POST", "/pair-setup", bytes(32))
                assert b"200 OK" in header and len(public_key) == 32
                proof = b"\x01\x00\x00\x00" + b"\x09" + bytes(31) + public_key
                for _ in range(16):
                    header, reply = request(pairing, "POST", "/pair-verify", proof)
                    assert b"200 OK" in header and len(reply) == 96
                header, _ = request(pairing, "POST", "/pair-verify", proof[:4] + bytes(32) + public_key)
                assert b"470" in header
            # Incomplete probes and rejected clients must leave the owner active.
            probes = [socket.create_connection(("127.0.0.1", port), timeout=3) for _ in range(6)]
            for probe in probes:
                probe.sendall(b"OP")
            challenger, header = connect_device("Other iPhone", port, password)
            assert b"409" in header
            challenger.close()
            if password:
                challenger, header = connect_device("Wrong password", port, "wrong")
                assert b"401" in header
                challenger.close()
            assert b"200 OK" in request(first, "OPTIONS", "*")[0]
            for probe in probes:
                probe.close()
            for streams in ([audio, mirror], [mirror]):
                header, _ = request(first, "SETUP", "/test", plistlib.dumps(
                    {"streams": streams}, fmt=plistlib.FMT_BINARY))
                assert b"200 OK" in header
                if len(streams) == 2:
                    media = socket.create_connection(("127.0.0.1", port + 100), timeout=3)
                    media.sendall(bytes(7))
                else:
                    try:
                        assert not media.recv(1), "old mirror socket survived rekey"
                    except ConnectionResetError:
                        pass
                    media.close()
            media = socket.create_connection(("127.0.0.1", port + 100), timeout=3)
            assert b"200 OK" in request(first, "TEARDOWN", "/test", plistlib.dumps(
                {"streams": [{"type": 96}, {"type": 110}]}, fmt=plistlib.FMT_BINARY))[0]
            try:
                assert not media.recv(1), "combined teardown left the mirror socket open"
            except ConnectionResetError:
                pass
            media.close()
            wait_for(lambda: source_status(primary) not in (b"Connected", b"Audio streaming"))
            assert b"200 OK" in request(first, "TEARDOWN", "/test")[0]
            assert not first.recv(1), "full teardown left the control socket open"
            wait_for(lambda: source_status(primary) == b"Waiting for an AirPlay device")
            restart(primary)
            first.close()
            release_source(primary)
            wait_destroy()
            cycle += 1
            resident, handles = process_resources()
            if cycle == 10:
                baseline = resident, handles
            if baseline:
                assert resident <= baseline[0] + 64 * 1024 * 1024, "stress memory growth exceeded 64 MiB"
                assert handles <= baseline[1] + 16, "stress handles or descriptors kept growing"
            now = time.monotonic()
            if now - last_report >= 30:
                print(f"Stress: {cycle} cycles, {now - began:.0f}s, peak RSS {resident / 1048576:.1f} MiB, "
                      f"handles/fds {handles}, CPU {time.process_time() - cpu_began:.1f}s", flush=True)
                last_report = now
        print(f"600-second OBS lifecycle stress PASS: {cycle} cycles", flush=True)

    if "--stress" in sys.argv:
        check_stress(settings)

    release_data(settings)
    print("Real OBS source startup, empty password, multiple sources and occupied port PASS")
    api("obs_shutdown", None, [])()
    print("Real OBS 32 shutdown PASS")
    if sys.platform == "darwin":
        installation.cleanup()
        print("macOS install and quarantine removal PASS")


if __name__ == "__main__":
    main()

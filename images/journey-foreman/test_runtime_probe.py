"""Fail-closed controls for the task image's measured runtime inventory."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "foreman_runtime_probe", Path(__file__).with_name("runtime_probe.py")
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class RuntimeProbeTests(unittest.TestCase):
    def test_resolves_libraries_and_loader_without_inventing_vdso_file(self):
        text = """ linux-vdso.so.1 (0x00007fff00000000)
 libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x0000700000000000)
 libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x0000700000000001)
 /lib64/ld-linux-x86-64.so.2 (0x0000700000000002)
"""
        self.assertEqual(probe.parse_ldd(text), (
            "/lib64/ld-linux-x86-64.so.2",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
        ))

    def test_missing_unknown_relative_or_static_dependencies_are_refused(self):
        for text in (
            "libstdc++.so.6 => not found\n",
            "libc.so.6 => relative/libc.so.6 (0x1234)\n",
            "not a dynamic executable\n",
            "statically linked\n",
            "unexpected diagnostic\n",
            "",
        ):
            with self.subTest(text=text), self.assertRaises(RuntimeError):
                probe.parse_ldd(text)

    def test_inventory_cannot_grow_without_bound(self):
        with self.assertRaises(RuntimeError):
            probe.parse_ldd("".join(
                f"lib{n}.so => /lib/lib{n}.so (0x1234)\n" for n in range(65)
            ))

    def test_exact_supported_runtime_and_embedded_components(self):
        probe.validate_versions(
            {"node": "24.22.1", "openssl": "3.5.9", "undici": "7.30.1"},
            "3.12.16", "CPython", ("glibc", "2.41"),
        )

    def test_missing_or_wrong_runtime_component_never_becomes_positive(self):
        good = {"node": "24.22.1", "openssl": "3.5.9", "undici": "7.30.1"}
        for versions, python, implementation, libc in (
            ({**good, "node": "24.22.2"}, "3.12.16", "CPython", ("glibc", "2.41")),
            ({**good, "openssl": "3.5.8"}, "3.12.16", "CPython", ("glibc", "2.41")),
            ({"node": "24.22.1"}, "3.12.16", "CPython", ("glibc", "2.41")),
            (good, "3.12.15", "CPython", ("glibc", "2.41")),
            (good, "3.12.16", "PyPy", ("glibc", "2.41")),
            (good, "3.12.16", "CPython", ("musl", "1.2.5")),
        ):
            with self.subTest(versions=versions, python=python, libc=libc), self.assertRaises(RuntimeError):
                probe.validate_versions(versions, python, implementation, libc)


if __name__ == "__main__":
    unittest.main()

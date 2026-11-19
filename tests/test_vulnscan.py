"""Parsing and behaviour of the vulnerability scanners."""

import os
import sys
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import vulnscan

NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT --script vuln" start="1" version="7.95">
<host><status state="up" reason="arp-response"/>
 <address addr="10.0.1.1" addrtype="ipv4"/>
 <port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="10.0p2"/>
  <script id="vulners" output="cpe:/a:openbsd:openssh:10.0p2:&#10;    &#9;CVE-2026-60002&#9;9.4&#9;https://vulners.com/cve/CVE-2026-60002&#10;    &#9;CVE-2025-61985&#9;3.6&#9;https://vulners.com/cve/CVE-2025-61985"/>
 </port>
 <port protocol="tcp" portid="80"><state state="open"/>
  <service name="http"/>
  <script id="http-vuln-cve2010-0738" output="/jmx-console/: Authentication was not required"/>
 </port>
</host>
</nmaprun>
"""


class SeverityTest(unittest.TestCase):
    def test_cvss_bands(self):
        self.assertEqual(vulnscan.Finding(cvss=9.8).severity, "critical")
        self.assertEqual(vulnscan.Finding(cvss=7.5).severity, "high")
        self.assertEqual(vulnscan.Finding(cvss=4.0).severity, "medium")
        self.assertEqual(vulnscan.Finding(cvss=2.1).severity, "low")
        self.assertEqual(vulnscan.Finding(cvss=0.0).severity, "info")

    def test_unknown_severity_sorts_last(self):
        self.assertGreater(vulnscan.severity_rank("nonsense"),
                           vulnscan.severity_rank("critical"))


class NmapParseTest(unittest.TestCase):
    def test_vulners_cve_and_score(self):
        findings = vulnscan.parse_nmap_findings(NMAP_XML)
        cves = {f.cve: f.cvss for f in findings}
        self.assertEqual(cves.get("CVE-2026-60002"), 9.4)
        self.assertEqual(cves.get("CVE-2025-61985"), 3.6)

    def test_host_ip_is_attached(self):
        findings = vulnscan.parse_nmap_findings(NMAP_XML)
        self.assertTrue(all(f.host == "10.0.1.1" for f in findings))

    def test_per_vuln_script_is_parsed(self):
        findings = vulnscan.parse_nmap_findings(NMAP_XML)
        scripts = {f.script for f in findings}
        self.assertIn("http-vuln-cve2010-0738", scripts)

    def test_broken_xml_yields_nothing(self):
        self.assertEqual(vulnscan.parse_nmap_findings("<not xml"), [])
        self.assertEqual(vulnscan.parse_nmap_findings(""), [])

    def test_script_error_is_not_a_finding(self):
        xml = ('<nmaprun><host><address addr="10.0.1.1" addrtype="ipv4"/>'
               '<port portid="80"><script id="http-vuln-x" '
               'output="ERROR: Script execution failed (use -d to debug)"/>'
               '</port></host></nmaprun>')
        findings = vulnscan.parse_nmap_findings(xml)
        self.assertEqual([f for f in findings if f.title.startswith("ERROR")], [])


class NucleiParseTest(unittest.TestCase):
    def test_jsonl_is_parsed(self):
        line = ('{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j",'
                '"severity":"critical","classification":{"cve-id":["CVE-2021-44228"],'
                '"cvss-score":10.0}},"matched-at":"10.0.1.1:8080"}')
        findings = vulnscan.parse_nuclei_findings(line)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cve, "CVE-2021-44228")
        self.assertEqual(findings[0].cvss, 10.0)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].host, "10.0.1.1:8080")

    def test_severity_without_a_score(self):
        line = ('{"template-id":"tech-detect","info":{"name":"Detect",'
                '"severity":"medium"},"matched-at":"10.0.1.1"}')
        findings = vulnscan.parse_nuclei_findings(line)
        self.assertEqual(findings[0].severity, "medium")
        self.assertGreater(findings[0].cvss, 0)

    def test_junk_lines_are_skipped(self):
        self.assertEqual(vulnscan.parse_nuclei_findings("not json\n\n"), [])
        self.assertEqual(vulnscan.parse_nuclei_findings(""), [])


class ScanTest(unittest.TestCase):
    def test_the_same_cve_from_two_engines_is_merged(self):
        """Both engines can report the same CVE; keep one record."""
        finding = vulnscan.Finding(cve="CVE-2021-44228", cvss=10.0,
                                   host="10.0.1.1", source="nuclei")
        other = vulnscan.Finding(cve="CVE-2021-44228", cvss=7.5,
                                 host="10.0.1.1", source="nmap")
        with unittest.mock.patch.object(vulnscan, "run_nmap_vuln",
                                        return_value=([other], "", {})), \
                unittest.mock.patch.object(vulnscan, "run_nuclei",
                                          return_value=([finding], "")):
            results, error, _services = vulnscan.scan(["10.0.1.1"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cvss, 10.0)
        self.assertEqual(error, "")

    def test_one_failing_engine_does_not_stop_the_other(self):
        found = vulnscan.Finding(cve="CVE-1", host="10.0.1.1")
        with unittest.mock.patch.object(vulnscan, "run_nmap_vuln",
                                        return_value=([], "nmap broke", {})), \
                unittest.mock.patch.object(vulnscan, "run_nuclei",
                                          return_value=([found], "")):
            results, error, _services = vulnscan.scan(["10.0.1.1"])
        self.assertEqual(len(results), 1)
        self.assertIn("nmap broke", error)

    def test_findings_come_back_worst_first(self):
        low = vulnscan.Finding(cve="CVE-1", cvss=1.0, host="h")
        high = vulnscan.Finding(cve="CVE-2", cvss=9.0, host="h")
        with unittest.mock.patch.object(vulnscan, "run_nmap_vuln",
                                        return_value=([low, high], "", {})), \
                unittest.mock.patch.object(vulnscan, "run_nuclei",
                                          return_value=([], "")):
            results, _error, _services = vulnscan.scan(["10.0.1.1"])
        self.assertEqual([f.cve for f in results], ["CVE-2", "CVE-1"])

    def test_a_cancelled_scan_stops(self):
        with unittest.mock.patch.object(vulnscan, "run_nmap_vuln") as nmap_run:
            results, error, _services = vulnscan.scan(
                ["10.0.1.1"], cancelled=lambda: True)
        self.assertEqual(results, [])
        self.assertEqual(error, "scan cancelled")
        nmap_run.assert_not_called()


class CancelTest(unittest.TestCase):
    """A cancel must stop the child at once, not after the timeout."""

    def test_the_child_is_terminated_on_cancel(self):
        """The scanner polls, so cancelling kills nmap straight away."""
        import subprocess
        import time

        started = time.time()

        def fake_popen(cmd, **kwargs):
            class FakeProc:
                def __init__(self):
                    self.polls = 0

                def communicate(self, timeout=None):
                    self.polls += 1
                    if self.polls < 3:
                        raise subprocess.TimeoutExpired(cmd, timeout)
                    return "", ""

                def terminate(self):
                    self.terminated = True

                def kill(self):
                    self.killed = True

                def poll(self):
                    return None

                def wait(self):
                    return 0

            proc = FakeProc()
            fake_popen.proc = proc
            return proc

        with unittest.mock.patch.object(vulnscan.subprocess, "Popen",
                                        side_effect=fake_popen):
            out, err, cancelled = vulnscan._run_child(
                ["nmap", "x"], timeout=600, cancelled=lambda: True)
        self.assertTrue(cancelled)
        self.assertLess(time.time() - started, 5)

    def test_a_cancelled_scan_reports_it(self):
        with unittest.mock.patch.object(vulnscan, "_run_child",
                                        return_value=("", "", True)):
            findings, error, _services = vulnscan.run_nmap_vuln(["10.0.1.1"])
        self.assertEqual(findings, [])
        self.assertEqual(error, "scan cancelled")

    def test_a_cancelled_nuclei_scan_reports_it(self):
        with unittest.mock.patch.object(vulnscan, "_run_child",
                                        return_value=("", "", True)), \
                unittest.mock.patch.object(vulnscan, "nuclei_binary",
                                          return_value="/usr/bin/nuclei"), \
                unittest.mock.patch.object(vulnscan, "nuclei_templates",
                                          return_value="/t"):
            findings, error = vulnscan.run_nuclei(["10.0.1.1"])
        self.assertEqual(findings, [])
        self.assertEqual(error, "scan cancelled")


class AvailabilityTest(unittest.TestCase):
    def test_missing_nuclei_is_reported(self):
        with unittest.mock.patch.object(vulnscan, "nuclei_binary",
                                        return_value=None):
            findings, error = vulnscan.run_nuclei(["10.0.1.1"])
        self.assertEqual(findings, [])
        self.assertIn("not installed", error)

    def test_missing_templates_are_reported(self):
        with unittest.mock.patch.object(vulnscan, "nuclei_binary",
                                        return_value="/usr/bin/nuclei"), \
                unittest.mock.patch.object(vulnscan, "nuclei_templates",
                                          return_value=None):
            findings, error = vulnscan.run_nuclei(["10.0.1.1"])
        self.assertEqual(findings, [])
        self.assertIn("no templates", error)

    def test_template_directory_is_found(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            open(os.path.join(tmp, "x.yaml"), "w").close()
            with unittest.mock.patch.dict(os.environ,
                                          {"NUCLEI_TEMPLATES": tmp}):
                self.assertEqual(vulnscan.nuclei_templates(), tmp)


if __name__ == "__main__":
    unittest.main()

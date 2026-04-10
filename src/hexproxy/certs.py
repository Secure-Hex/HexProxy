from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from threading import Lock

from .preferences import default_config_dir


def default_certificate_dir() -> Path:
    return default_config_dir() / "certs"


class CertificateAuthority:
    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.hosts_dir = self.base_dir / "hosts"
        self.ca_cert = self.base_dir / "hexproxy-ca.crt"
        self.ca_key = self.base_dir / "hexproxy-ca.key"
        self.ca_serial = self.base_dir / "hexproxy-ca.srl"
        self._lock = Lock()

    def cert_path(self) -> Path:
        return self.ca_cert

    def is_ready(self) -> bool:
        with self._lock:
            return self.ca_cert.exists() and self.ca_key.exists()

    def ensure_ready(self) -> Path:
        with self._lock:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            self.hosts_dir.mkdir(parents=True, exist_ok=True)
            if self.ca_cert.exists() and self.ca_key.exists():
                return self.ca_cert

            openssl = self._openssl_path()

            config_text = "\n".join(
                [
                    "[req]",
                    "prompt = no",
                    "distinguished_name = dn",
                    "x509_extensions = v3_ca",
                    "",
                    "[dn]",
                    "CN = HexProxy Root CA",
                    "",
                    "[v3_ca]",
                    "basicConstraints = critical,CA:TRUE,pathlen:1",
                    "keyUsage = critical,keyCertSign,cRLSign",
                    "subjectKeyIdentifier = hash",
                    "authorityKeyIdentifier = keyid:always,issuer",
                ]
            )
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".cnf", delete=False) as handle:
                config_path = Path(handle.name)
                handle.write(config_text)
            try:
                subprocess.run(
                    [
                        openssl,
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-days",
                        "3650",
                        "-keyout",
                        str(self.ca_key),
                        "-out",
                        str(self.ca_cert),
                        "-config",
                        str(config_path),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as exc:
                raise RuntimeError(exc.stderr.strip() or "failed to generate HexProxy CA") from exc
            finally:
                config_path.unlink(missing_ok=True)
        return self.ca_cert

    def issue_server_cert(self, host: str) -> tuple[Path, Path]:
        self.ensure_ready()
        safe_name = self._safe_name(host)
        cert_path = self.hosts_dir / f"{safe_name}.crt"
        key_path = self.hosts_dir / f"{safe_name}.key"
        if self._host_cert_is_current(cert_path, key_path):
            return cert_path, key_path

        with self._lock:
            if self._host_cert_is_current(cert_path, key_path):
                return cert_path, key_path

            openssl = self._openssl_path()

            with tempfile.TemporaryDirectory(prefix="hexproxy-cert-") as tmpdir:
                temp_dir = Path(tmpdir)
                config_path = temp_dir / "leaf.cnf"
                csr_path = temp_dir / "leaf.csr"
                config_path.write_text(self._leaf_config(host), encoding="utf-8")

                try:
                    subprocess.run(
                        [
                            openssl,
                            "req",
                            "-new",
                            "-newkey",
                            "rsa:2048",
                            "-nodes",
                            "-keyout",
                            str(key_path),
                            "-out",
                            str(csr_path),
                            "-config",
                            str(config_path),
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    subprocess.run(
                        [
                            openssl,
                            "x509",
                            "-req",
                            "-in",
                            str(csr_path),
                            "-CA",
                            str(self.ca_cert),
                            "-CAkey",
                            str(self.ca_key),
                            "-CAcreateserial",
                            "-CAserial",
                            str(self.ca_serial),
                            "-days",
                            "90",
                            "-sha256",
                            "-out",
                            str(cert_path),
                            "-extfile",
                            str(config_path),
                            "-extensions",
                            "req_ext",
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                except subprocess.CalledProcessError as exc:
                    cert_path.unlink(missing_ok=True)
                    key_path.unlink(missing_ok=True)
                    raise RuntimeError(exc.stderr.strip() or f"failed to issue certificate for {host}") from exc

        return cert_path, key_path

    def _host_cert_is_current(self, cert_path: Path, key_path: Path) -> bool:
        if not cert_path.exists() or not key_path.exists():
            return False
        ca_mtime = max(self.ca_cert.stat().st_mtime, self.ca_key.stat().st_mtime)
        leaf_mtime = min(cert_path.stat().st_mtime, key_path.stat().st_mtime)
        return leaf_mtime >= ca_mtime

    def regenerate(self) -> Path:
        with self._lock:
            if self.hosts_dir.exists():
                shutil.rmtree(self.hosts_dir)
            self.ca_cert.unlink(missing_ok=True)
            self.ca_key.unlink(missing_ok=True)
            self.ca_serial.unlink(missing_ok=True)
        return self.ensure_ready()

    @staticmethod
    def _openssl_path() -> str:
        openssl = shutil.which("openssl")
        if openssl is not None:
            return openssl
        if os.name == "nt":
            raise RuntimeError("openssl is required on Windows; install OpenSSL and add openssl.exe to PATH")
        raise RuntimeError("openssl is required to generate HexProxy certificates")

    @staticmethod
    def _safe_name(host: str) -> str:
        return "".join(character if character.isalnum() or character in {"-", "_", "."} else "_" for character in host)

    @staticmethod
    def _leaf_config(host: str) -> str:
        alt_name = CertificateAuthority._subject_alt_name(host)
        return "\n".join(
            [
                "[req]",
                "prompt = no",
                "distinguished_name = dn",
                "req_extensions = req_ext",
                "",
                "[dn]",
                f"CN = {host}",
                "",
                "[req_ext]",
                "basicConstraints = critical,CA:FALSE",
                "keyUsage = critical,digitalSignature,keyEncipherment",
                "extendedKeyUsage = serverAuth",
                f"subjectAltName = {alt_name}",
            ]
        )

    @staticmethod
    def _subject_alt_name(host: str) -> str:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return f"DNS:{host}"
        return f"IP:{host}"

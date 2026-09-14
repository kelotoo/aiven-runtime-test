import http.server
import json
import os
import socket
import subprocess
import urllib.request

RECON_TOKEN = "teteglDDJFIFHFBgfueub"

INTERNAL_DNS_NAMES = [
    "kubernetes.default.svc",
    "kubernetes.default",
    "metadata.google.internal",
    "nomad.service.consul",
    "vault.service.consul",
    "consul.service.consul",
]

GATEWAY_PORTS = [22, 2375, 2376, 6443, 8443, 10250, 10255, 4646, 4647, 4648, 8200, 8500]
LOCALHOST_PORTS = [22, 80, 443, 2375, 2376, 5000, 8000, 8001, 9000, 9090, 10248, 10249, 10250, 10255, 4646, 4647, 4648, 8200, 8500]

SENSITIVE_KEYWORDS = ["PASSWORD", "SECRET", "TOKEN", "KEY", "PASS", "CREDENTIAL", "AUTH"]

SOCKET_CANDIDATES = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/podman/podman.sock",
    "/run/podman/podman.sock",
    "/run/user/0/podman/podman.sock",
    "/var/run/crio/crio.sock",
    "/run/containerd/containerd.sock",
    "/hostfs/var/run/docker.sock",
    "/hostfs/run/podman/podman.sock",
]

IDENTIFY_ENDPOINTS = {
    "nomad_agent_self": "http://{host}:4646/v1/agent/self",
    "vault_sys_health": "http://{host}:8200/v1/sys/health",
    "consul_agent_self": "http://{host}:8500/v1/agent/self",
}

# A fully-privileged, unrestricted container normally has this exact 64-bit capability mask
# (all standard capability bits set) in CapEff/CapBnd. Used only as a comparison reference,
# never used to actually exercise any capability.
FULL_CAP_MASK_HEX = "0000003fffffffff"


def redact_env():
    out = {}
    for k, v in os.environ.items():
        if any(kw in k.upper() for kw in SENSITIVE_KEYWORDS):
            out[k] = f"<redacted, len={len(v)}>"
        else:
            out[k] = v
    return out


def get_default_gateway():
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == "00000000":
                    hexgw = fields[2]
                    return socket.inet_ntoa(bytes.fromhex(hexgw)[::-1])
    except Exception as e:
        return f"error: {e}"
    return None


def check_port(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except Exception:
        return "closed/filtered"


def check_metadata_endpoint(url, headers=None, timeout=2):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(500).decode(errors="replace")
            return {"status": resp.status, "body_preview": body}
    except Exception as e:
        return {"error": str(e)}


def resolve(name):
    try:
        return socket.gethostbyname(name)
    except Exception as e:
        return f"error: {e}"


def read_file_safe(path, max_bytes=2000):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(max_bytes)
    except Exception as e:
        return f"error: {e}"


def list_sockets():
    return {p: os.path.exists(p) for p in SOCKET_CANDIDATES}


def get_ps_aux():
    try:
        out = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=3)
        return out.stdout[:3000]
    except Exception as e:
        return f"error: {e}"


def identify_services(hosts):
    results = {}
    for host in hosts:
        if not host:
            continue
        for name, template in IDENTIFY_ENDPOINTS.items():
            url = template.format(host=host)
            key = f"{host}:{name}"
            results[key] = check_metadata_endpoint(url, timeout=2)
    return results


def check_capabilities():
    """Passive-only: reads our own /proc/self/status capability masks. Does not exercise
    any capability, does not attempt privileged operations - detection only."""
    result = {}
    status = read_file_safe("/proc/self/status", max_bytes=4000)
    if status.startswith("error:"):
        return {"error": status}
    caps = {}
    for line in status.splitlines():
        if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:")):
            k, v = line.split(":", 1)
            caps[k.strip()] = v.strip()
    result["raw"] = caps
    eff = caps.get("CapEff", "")
    result["cap_eff_is_full_privileged_mask"] = (eff == FULL_CAP_MASK_HEX)
    return result


def check_hostfs_mount():
    """Passive-only: checks for existence of a /hostfs mount point (from a
    `volumes: - /:/hostfs:ro` compose directive) and lists top-level directory NAMES only.
    Never reads file contents."""
    result = {"mount_point_exists": os.path.isdir("/hostfs")}
    if result["mount_point_exists"]:
        try:
            entries = sorted(os.listdir("/hostfs"))
            result["top_level_entries"] = entries[:60]
            fhs_markers = {"etc", "proc", "sys", "dev", "var", "usr", "bin"}
            result["looks_like_real_root_fs"] = fhs_markers.issubset(set(entries))
            own_hostname = read_file_safe("/etc/hostname").strip()
            host_hostname = read_file_safe("/hostfs/etc/hostname").strip()
            result["own_hostname"] = own_hostname
            result["hostfs_etc_hostname"] = host_hostname
            result["hostfs_hostname_differs_from_own"] = (
                host_hostname != own_hostname and not host_hostname.startswith("error:")
            )
        except Exception as e:
            result["listdir_error"] = str(e)
    return result


def check_dev_listing():
    """Passive-only: lists /dev entry names (not contents) - a minimal unprivileged
    container normally has a small fixed set (null, zero, random, urandom, tty, console,
    ptmx, pts/, shm, mqueue, fd). Real block/char devices (sda, nvme0n1, kmsg, mem, etc.)
    appearing here would indicate device passthrough from a privileged/host context."""
    try:
        return sorted(os.listdir("/dev"))
    except Exception as e:
        return f"error: {e}"


def check_network_interfaces():
    """Passive-only: lists network interface names via /sys/class/net - a normal
    container has just lo + one veth/eth virtual interface. Seeing many interfaces
    (docker0/podman0 bridge, multiple veth* pairs for OTHER containers, physical NIC
    names) would indicate network_mode: host was honored."""
    try:
        return sorted(os.listdir("/sys/class/net"))
    except Exception as e:
        return f"error: {e}"


def run_recon():
    result = {}
    result["hostname"] = socket.gethostname()
    try:
        result["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception as e:
        result["local_ip"] = f"error: {e}"

    sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    result["k8s_serviceaccount_token_present"] = os.path.exists(sa_token_path)
    if result["k8s_serviceaccount_token_present"]:
        result["k8s_serviceaccount_token_note"] = (
            "present but NOT read/used - report to program, do not test scope"
        )

    gw = get_default_gateway()
    result["default_gateway"] = gw

    result["dns_resolution"] = {name: resolve(name) for name in INTERNAL_DNS_NAMES}

    if gw:
        result["gateway_port_scan"] = {
            str(p): check_port(gw, p) for p in GATEWAY_PORTS
        }

    result["localhost_port_scan"] = {
        str(p): check_port("127.0.0.1", p) for p in LOCALHOST_PORTS
    }

    result["aws_metadata_v1"] = check_metadata_endpoint(
        "http://169.254.169.254/latest/meta-data/"
    )
    result["gcp_metadata"] = check_metadata_endpoint(
        "http://169.254.169.254/computeMetadata/v1/",
        headers={"Metadata-Flavor": "Google"},
    )
    result["azure_metadata"] = check_metadata_endpoint(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        headers={"Metadata": "true"},
    )

    identify_hosts = set()
    for host_label, host_val in (("gw", gw), ("localhost", "127.0.0.1")):
        scan = result.get("gateway_port_scan", {}) if host_label == "gw" else result.get("localhost_port_scan", {})
        for p in ("4646", "8200", "8500"):
            if scan.get(p) == "open":
                identify_hosts.add(host_val if host_label == "gw" else "127.0.0.1")

    result["service_identification"] = identify_services(identify_hosts) if identify_hosts else {
        "note": "skipped - none of the Nomad/Vault/Consul ports showed open in the port scans above"
    }

    result["env_vars"] = redact_env()
    result["containerenv_file"] = read_file_safe("/run/.containerenv")
    result["proc1_cgroup"] = read_file_safe("/proc/1/cgroup")
    result["sockets_present"] = list_sockets()
    result["ps_aux"] = get_ps_aux()

    # New: compose-directive-injection detection (privileged / cap_add / volume bind-mount)
    result["capabilities"] = check_capabilities()
    result["hostfs_mount_test"] = check_hostfs_mount()
    result["dev_listing"] = check_dev_listing()
    result["network_interfaces"] = check_network_interfaces()

    return result


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path.startswith("/recon"):
            token = None
            if "token=" in self.path:
                token = self.path.split("token=", 1)[1].split("&", 1)[0]
            if token != RECON_TOKEN:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"forbidden")
                return
            data = run_recon()
            body = json.dumps(data, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()

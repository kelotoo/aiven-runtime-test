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
]

GATEWAY_PORTS = [22, 2375, 2376, 6443, 8443, 10250, 10255]
LOCALHOST_PORTS = [22, 80, 443, 2375, 2376, 5000, 8000, 8001, 9000, 9090, 10248, 10249, 10250, 10255]

SENSITIVE_KEYWORDS = ["PASSWORD", "SECRET", "TOKEN", "KEY", "PASS", "CREDENTIAL", "AUTH"]

SOCKET_CANDIDATES = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/podman/podman.sock",
    "/run/podman/podman.sock",
    "/run/user/0/podman/podman.sock",
    "/var/run/crio/crio.sock",
    "/run/containerd/containerd.sock",
]


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


def run_recon():
    result = {}
    result["hostname"] = socket.gethostname()
    try:
        result["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception as e:
        result["local_ip"] = f"error: {e}"

    sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
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

    result["env_vars"] = redact_env()
    result["containerenv_file"] = read_file_safe("/run/.containerenv")
    result["proc1_cgroup"] = read_file_safe("/proc/1/cgroup")
    result["sockets_present"] = list_sockets()
    result["ps_aux"] = get_ps_aux()

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
    result["aws_metadata_v1"] = ch

"""Static checks of Compose, Dockerfiles and Kubernetes manifests (spec 11.2 to 11.4, Appendix G).

Nothing here needs Docker or a cluster. If `docker compose` or `kubectl` exist, they are also run.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

DEPLOY = Path(__file__).resolve().parents[1]
COMPOSE = DEPLOY / "compose" / "docker-compose.yml"
K8S = DEPLOY / "k8s"
DOCKER = DEPLOY / "docker"

APP_SERVICES = {"generator": 8300, "ingestor": 8301, "detector": 8200, "ml": 8100, "api": 8000, "dashboard": 8501}
BUDGET_MB = {"opensearch": 1200, "redis": 200, "generator": 300, "ingestor": 200, "detector": 400, "ml": 1000,
             "api": 500, "dashboard": 500, "mlflow": 300}


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())


def mb(value):
    m = re.fullmatch(r"(\d+)([mg])", str(value))
    return int(m.group(1)) * (1024 if m.group(2) == "g" else 1)


# ----------------------------------------------------------------- compose
def test_compose_services_and_network(compose):
    assert set(compose["services"]) == set(BUDGET_MB)
    assert "hc-net" in compose["networks"] and {"hc-data", "os-data"} <= set(compose["volumes"])
    for name, svc in compose["services"].items():
        assert svc["networks"] == ["hc-net"], name


def test_compose_memory_budget(compose):
    for name, limit in BUDGET_MB.items():
        assert mb(compose["services"][name]["mem_limit"]) == limit, name
    assert sum(BUDGET_MB.values()) <= 4700


def test_compose_every_service_has_healthcheck(compose):
    for name, svc in compose["services"].items():
        assert svc["healthcheck"]["test"], name
        assert svc["healthcheck"]["retries"] >= 10, name


def test_compose_depends_on_healthy(compose):
    for name, svc in compose["services"].items():
        for dep, cond in (svc.get("depends_on") or {}).items():
            assert cond == {"condition": "service_healthy"}, f"{name}->{dep}"
            assert dep in compose["services"]
    deps = {n: set(s.get("depends_on") or {}) for n, s in compose["services"].items()}
    assert deps["ingestor"] == {"redis", "opensearch"}
    assert {"redis", "opensearch"} <= deps["detector"] and "opensearch" in deps["ml"]
    assert {"api", "generator"} <= deps["dashboard"]


def test_compose_ports_loopback_except_dashboard(compose):
    for name, svc in compose["services"].items():
        for port in svc.get("ports", []):
            host = port.split(":")[0]
            assert host == ("0.0.0.0" if name == "dashboard" else "127.0.0.1"), (name, port)
    published = {n: [p.split(":")[-1] for p in s["ports"]] for n, s in compose["services"].items()}
    for name, port in APP_SERVICES.items():
        assert published[name] == [str(port)]
    assert published["opensearch"] == ["9200"] and published["redis"] == ["6379"] and published["mlflow"] == ["5000"]


def test_compose_opensearch_settings(compose):
    os_svc = compose["services"]["opensearch"]
    assert os_svc["image"].startswith("${OPENSEARCH_IMAGE:-opensearchproject/opensearch:2.")
    env = os_svc["environment"]
    assert env["discovery.type"] == "single-node"
    assert env["DISABLE_SECURITY_PLUGIN"] == "true" and env["DISABLE_INSTALL_DEMO_CONFIG"] == "true"
    assert env["OPENSEARCH_JAVA_OPTS"] == "-Xms512m -Xmx512m" and env["bootstrap.memory_lock"] == "false"
    assert "os-data:/usr/share/opensearch/data" in os_svc["volumes"]
    assert compose["services"]["redis"]["image"] == "redis:7-alpine"


def test_compose_builds_use_repo_root_and_existing_dockerfiles(compose):
    for name in list(APP_SERVICES) + ["mlflow"]:
        build = compose["services"][name]["build"]
        assert build["context"] == "../.."
        assert (DEPLOY.parent / build["dockerfile"]).is_file(), name


def test_compose_api_key_is_required_not_hardcoded(compose):
    text = COMPOSE.read_text()
    assert "${HC_API_KEY:?" in text
    assert not re.search(r"HC_API_KEY:\s*['\"]?[A-Za-z0-9]{8,}", text.replace("${HC_API_KEY:?", ""))


def test_compose_volume_for_stateful_services(compose):
    for name in ("generator", "ingestor", "detector", "ml", "api", "mlflow"):
        assert "hc-data:/data" in compose["services"][name]["volumes"], name


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_docker_compose_config_validates():
    env = dict(os.environ, HC_API_KEY="unit-test-key")
    try:
        proc = subprocess.run(["docker", "compose", "-f", str(COMPOSE), "config", "-q"], env=env,
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("docker compose not usable here")
    if "unknown shorthand flag" in proc.stderr or "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin missing")
    assert proc.returncode == 0, proc.stderr


def test_compose_fails_clearly_without_api_key():
    text = COMPOSE.read_text()
    assert "copy .env.example to .env" in text


# ----------------------------------------------------------------- Dockerfiles
@pytest.mark.parametrize("name,port", list(APP_SERVICES.items()) + [("mlflow", 5000)])
def test_dockerfile_pattern(name, port):
    text = (DOCKER / f"Dockerfile.{name}").read_text()
    assert text.count("FROM ") == 1 and "FROM python:3.11-slim" in text
    assert "useradd --create-home --uid 10001 hc" in text and re.search(r"^USER hc$", text, re.M)
    assert f"EXPOSE {port}" in text and "HEALTHCHECK" in text and f"localhost:{port}" in text
    assert "--no-cache-dir" in text
    assert not re.search(r"gcc|build-essential|apt-get|apk add", text)
    assert "chown hc:hc /data" in text
    if name != "mlflow":
        for line in ("COPY common/ /app/common/", "COPY libs/ /app/libs/", f"COPY services/{name}/ /app/services/{name}/"):
            assert line in text
        assert f"PYTHONPATH=/app/common:/app/libs:/app/services/{name}" in text
        assert f"-r /app/services/{name}/requirements.txt" in text
    assert re.search(r'^CMD \["sh", "-c", "exec ', text, re.M)


def test_generator_and_ingestor_commands():
    assert "exec python -m generator serve" in (DOCKER / "Dockerfile.generator").read_text()
    assert "exec python -m ingestor run" in (DOCKER / "Dockerfile.ingestor").read_text()
    assert "/_stcore/health" in (DOCKER / "Dockerfile.dashboard").read_text()


# ----------------------------------------------------------------- env example
def test_env_example_covers_section_4_and_has_no_secrets():
    text = (DEPLOY / "compose" / ".env.example").read_text()
    keys = dict(line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))
    required = {"HC_ENV", "HC_LOG_LEVEL", "HC_REDIS_URL", "HC_OPENSEARCH_URL", "HC_EVENTS_INDEX_PREFIX",
                "HC_ALERTS_INDEX", "HC_FINDINGS_INDEX", "HC_API_KEY", "HC_API_URL", "HC_ML_URL",
                "HC_GENERATOR_URL", "HC_DB_URL", "HC_AUDIT_PATH", "HC_MODEL_DIR", "HC_MLFLOW_URI",
                "LLM_PROVIDER", "LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL", "LLM_TIMEOUT_S"}
    assert required <= set(keys)
    assert keys["HC_API_KEY"].startswith("<") and keys["LLM_API_KEY"] == "" and keys["LLM_PROVIDER"] == "none"


# ----------------------------------------------------------------- Kubernetes
EXPECTED = ["00-namespace.yaml", "10-configmap.yaml", "11-secret.example.yaml", "20-redis.yaml", "21-opensearch.yaml",
            "30-ml.yaml", "31-api.yaml", "32-detector.yaml", "33-ingestor.yaml", "34-generator.yaml",
            "35-dashboard.yaml", "36-mlflow.yaml"]


def k8s_docs():
    out = []
    for name in EXPECTED:
        out += [(name, d) for d in yaml.safe_load_all((K8S / name).read_text()) if d]
    return out


def test_k8s_files_exist_and_parse():
    assert sorted(p.name for p in K8S.glob("*.yaml")) == EXPECTED
    for name, doc in k8s_docs():
        assert doc["apiVersion"] and doc["kind"] and doc["metadata"]["name"], name


def test_k8s_labels_everywhere():
    for name, doc in k8s_docs():
        assert doc["metadata"]["labels"]["app.kubernetes.io/part-of"] == "huntcopilot", (name, doc["kind"])
        assert doc["metadata"].get("namespace", "huntcopilot") == "huntcopilot" or doc["kind"] == "Namespace"


def workloads():
    return [(n, d) for n, d in k8s_docs() if d["kind"] in ("Deployment", "StatefulSet")]


def test_k8s_workloads_have_resources_probes_and_nonroot():
    names = set()
    for fname, d in workloads():
        pod = d["spec"]["template"]["spec"]
        names.add(d["metadata"]["name"])
        assert pod["securityContext"]["runAsNonRoot"] is True, fname
        assert d["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/part-of"] == "huntcopilot"
        for c in pod["containers"]:
            res = c["resources"]
            assert res["requests"]["memory"] and res["limits"]["memory"] and res["requests"]["cpu"], fname
            assert c["livenessProbe"] and c["readinessProbe"], fname
            assert c["securityContext"]["allowPrivilegeEscalation"] is False
    assert names == set(BUDGET_MB)


def test_k8s_app_probes_use_health_paths():
    for fname, d in workloads():
        c = d["spec"]["template"]["spec"]["containers"][0]
        name = d["metadata"]["name"]
        if name in APP_SERVICES or name == "mlflow":
            want = "/_stcore/health" if name == "dashboard" else "/health"
            assert c["livenessProbe"]["httpGet"]["path"] == want and c["readinessProbe"]["httpGet"]["path"] == want


def test_k8s_memory_limits_match_budget():
    for fname, d in workloads():
        name = d["metadata"]["name"]
        limit = d["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"]
        assert int(limit.removesuffix("Mi")) == BUDGET_MB[name], name


def test_k8s_config_via_configmap_and_secret():
    for fname, d in workloads():
        if d["metadata"]["name"] in APP_SERVICES:
            refs = d["spec"]["template"]["spec"]["containers"][0]["envFrom"]
            assert {"configMapRef": {"name": "hc-config"}} in refs and {"secretRef": {"name": "hc-secrets"}} in refs
    cm = next(d for n, d in k8s_docs() if d["kind"] == "ConfigMap")["data"]
    for url in ("HC_REDIS_URL", "HC_OPENSEARCH_URL", "HC_API_URL", "HC_ML_URL", "HC_GENERATOR_URL"):
        assert cm[url].split("//")[1].split(":")[0] in BUDGET_MB, url
    secret = next(d for n, d in k8s_docs() if d["kind"] == "Secret")
    assert secret["stringData"]["HC_API_KEY"].startswith("<") and "example" in (K8S / "11-secret.example.yaml").name
    assert "LLM_API_KEY" not in cm and "HC_API_KEY" not in cm


def test_k8s_services_and_nodeport():
    svcs = {d["metadata"]["name"]: d for n, d in k8s_docs() if d["kind"] == "Service"}
    assert set(svcs) == set(BUDGET_MB)
    dash = svcs["dashboard"]["spec"]
    assert dash["type"] == "NodePort" and dash["ports"][0]["nodePort"] == 30501 and dash["ports"][0]["port"] == 8501
    for name, port in APP_SERVICES.items():
        assert svcs[name]["spec"]["ports"][0]["port"] == port
    assert svcs["opensearch"]["spec"]["ports"][0]["port"] == 9200


def test_k8s_opensearch_is_statefulset_with_heap_settings():
    d = next(d for n, d in k8s_docs() if d["kind"] == "StatefulSet")
    env = {e["name"]: e["value"] for e in d["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["OPENSEARCH_JAVA_OPTS"] == "-Xms512m -Xmx512m" and env["discovery.type"] == "single-node"
    assert d["spec"]["volumeClaimTemplates"][0]["metadata"]["name"] == "os-data"
    assert d["spec"]["serviceName"] == "opensearch"


@pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl not installed")
def test_kubectl_dry_run_client():
    proc = subprocess.run(["kubectl", "apply", "--dry-run=client", "--validate=false", "-f", str(K8S)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_verify_stack_script_is_valid_bash():
    script = DEPLOY / "verify_stack.sh"
    assert script.is_file() and script.read_text().startswith("#!/usr/bin/env bash")
    if shutil.which("bash"):
        assert subprocess.run(["bash", "-n", str(script)], capture_output=True).returncode == 0
    assert "docker manifest inspect" in script.read_text() and "ingest-file" in script.read_text()


def test_dashboard_dockerfile_installs_its_requirements():
    text = (DOCKER / "Dockerfile.dashboard").read_text()
    assert "COPY services/dashboard/ /app/services/dashboard/" in text
    assert "-r /app/services/dashboard/requirements.txt" in text

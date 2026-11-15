#!/usr/bin/env bash
# M1 real-stack check (needs Docker; kubectl is optional). Prints a report; exit code 1 if a check fails.
#   bash deploy/verify_stack.sh 2>&1 | tee verify_report.txt
set -u
cd "$(dirname "$0")/compose" || exit 2
FAIL=0
say() { printf '\n== %s\n' "$*"; }
bad() { echo "FAIL: $*"; FAIL=1; }

if [ ! -f .env ]; then
  cp .env.example .env
  sed -i "s|^HC_API_KEY=.*|HC_API_KEY=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')|" .env
  echo "created .env with a random HC_API_KEY"
fi
IMG=$(grep '^OPENSEARCH_IMAGE=' .env | cut -d= -f2-)

say "1. OpenSearch image $IMG (arm64 needed on the ARM VM)"
if docker manifest inspect "$IMG" > /tmp/hc_manifest.json 2>/tmp/hc_manifest.err; then
  grep -o '"architecture": *"[a-z0-9]*"' /tmp/hc_manifest.json | sort -u
  grep -q '"architecture": *"arm64"' /tmp/hc_manifest.json && echo "arm64: YES" || bad "no arm64 variant"
else cat /tmp/hc_manifest.err; bad "manifest not found"; fi

say "2. docker compose config"
docker compose config -q && echo "config OK" || bad "compose config"

say "3. build dashboard image (uses services/dashboard/requirements.txt)"
docker compose build dashboard 2>&1 | tail -5 || bad "dashboard build"

say "4. start redis, opensearch, generator, ingestor"
docker compose up -d --build redis opensearch generator ingestor || bad "compose up"
for svc in redis opensearch generator ingestor; do
  ok=0
  for _ in $(seq 1 60); do
    st=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q "$svc")" 2>/dev/null)
    [ "$st" = "healthy" ] && ok=1 && break
    sleep 5
  done
  echo "$svc: $([ $ok = 1 ] && echo healthy || echo NOT healthy)"; [ $ok = 1 ] || bad "$svc not healthy"
done

say "5. eval run to redis, ingest rate through the stream"
T0=$(date +%s.%N)
SUMMARY=$(docker compose run --rm -T generator python -m generator run --profile eval --scenarios apt_chain --seed 2002 --out redis | tail -1)
echo "$SUMMARY"
N=$(echo "$SUMMARY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["events"])')
for _ in $(seq 1 300); do
  IDX=$(curl -s http://127.0.0.1:8301/health | python3 -c 'import json,sys; print(json.load(sys.stdin).get("indexed",0))' 2>/dev/null || echo 0)
  [ "${IDX:-0}" -ge "$N" ] && break
  sleep 1
done
T1=$(date +%s.%N)
python3 - "$N" "${IDX:-0}" "$T0" "$T1" <<'PY'
import sys
n, idx, t0, t1 = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
print(f"events {n}, indexed {idx}, {t1 - t0:.1f} s including generation, {idx / (t1 - t0):.0f} events/s end to end (target 800)")
PY
echo "DLQ length: $(docker compose exec -T redis redis-cli XLEN hc:dlq)"
curl -s http://127.0.0.1:8301/health; echo
curl -s 'http://127.0.0.1:9200/hc-events-*/_count'; echo

say "6. pure indexing rate with ingest-file (re-ingest must not add documents)"
docker compose run --rm -T generator python -m generator run --profile eval --scenarios apt_chain --seed 2002 --out jsonl --jsonl-path /data/eval.jsonl | tail -1
docker compose run --rm -T ingestor python -m ingestor ingest-file /data/eval.jsonl | tail -1
curl -s 'http://127.0.0.1:9200/hc-events-*/_count'; echo "(count must be unchanged after the re-ingest)"

say "7. kubectl dry-run"
if command -v kubectl >/dev/null 2>&1; then
  kubectl apply --dry-run=client -f ../k8s/ || bad "kubectl dry-run"
else echo "kubectl not installed: skipped"; fi

say "RESULT: $([ $FAIL = 0 ] && echo PASS || echo FAIL)"
exit $FAIL

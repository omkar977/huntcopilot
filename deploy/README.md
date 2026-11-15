# deploy (module M1)

Docker Compose, Dockerfiles and Kubernetes manifests for HuntCopilot (spec 11.2 to 11.4).

## Compose
```
cd deploy/compose
cp .env.example .env          # then set HC_API_KEY to a long random string
docker compose up -d --build
docker compose ps             # wait until every service is healthy
```
Load data (training first, then the demo dataset):
```
docker compose run --rm generator python -m generator run --profile benign_train --seed 1001 --out redis
docker compose run --rm generator python -m generator run --profile eval --scenarios apt_chain --seed 2002 --out redis
curl -s http://127.0.0.1:8301/health        # ingestor counters
```
Stop with `docker compose down` (add `-v` to delete the data volumes).

Notes
- The OpenSearch image tag is set by OPENSEARCH_IMAGE in `.env` (default 2.17.1). Check that the tag has an arm64 variant before building on the ARM VM.
- Set `vm.max_map_count=262144` on the host if OpenSearch does not start (spec Appendix N).
- Dockerfiles are in `deploy/docker/Dockerfile.<service>`. The last line of each is the start command; change it there if a module starts differently (detector, ml and api are assumed to use `main.py`, and `main:app` for the FastAPI ones).
- Dockerfiles copy `services/<name>/requirements.txt`, which each module owner supplies.

## Kubernetes
```
docker build -f deploy/docker/Dockerfile.api -t huntcopilot/api:dev .      # repeat for each service, import into the cluster
cp deploy/k8s/11-secret.example.yaml deploy/k8s/11-secret.yaml              # edit the values
kubectl apply --dry-run=client -f deploy/k8s/
kubectl apply -f deploy/k8s/00-namespace.yaml -f deploy/k8s/10-configmap.yaml -f deploy/k8s/11-secret.yaml
kubectl apply -f deploy/k8s/
```
The dashboard is on NodePort 30501. All pods share one ReadWriteOnce volume, so run on a single node.

## Dashboard page 7
The page lives in `services/dashboard/pages/7_Simulation.py` (moved by the Lead at merge).

## Check the real stack
`bash deploy/verify_stack.sh 2>&1 | tee verify_report.txt` runs, on a machine with Docker: the OpenSearch arm64 check, `docker compose config`, the dashboard image build, the four core services, an eval run to Redis with the ingest rate and DLQ count, a re-ingest idempotency check, and `kubectl apply --dry-run=client` if kubectl exists.

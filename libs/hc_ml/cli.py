"""Command line: train and evaluate from JSONL files (no OpenSearch needed).

  python -m hc_ml train --events data/train.jsonl --model-dir /tmp/models --seed 1001
  python -m hc_ml evaluate --events data/eval.jsonl --model-dir /tmp/models
"""
from __future__ import annotations

import argparse
import json

from .evaluate import evaluate_windows
from .jsonl import read_jsonl, tag_train
from .model import AnomalyModel


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="hc_ml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    tr = sub.add_parser("train")
    tr.add_argument("--events", required=True)
    tr.add_argument("--model-dir", required=True)
    tr.add_argument("--seed", type=int, default=1001)
    tr.add_argument("--force-train-tag", action="store_true", help="tag every event as train (benign_train files)")
    tr.add_argument("--global-only", action="store_true", help="skip the separate workstation/server baselines")
    tr.add_argument("--per-host-rare", action="store_true", help="(default on) rare_* scores from each host's own history")
    tr.add_argument("--no-per-host-rare", action="store_true", help="turn per-host rare_* scores off")
    tr.add_argument("--beacon-min-net", type=int, default=0, help="beacon_cv only when n_net is at least this")
    ev = sub.add_parser("evaluate")
    ev.add_argument("--events", required=True)
    ev.add_argument("--model-dir", required=True)
    args = ap.parse_args(argv)
    events = read_jsonl(args.events)
    if args.cmd == "train":
        if args.force_train_tag:
            tag_train(events)
        model = AnomalyModel.train(events, seed=args.seed, per_group=not args.global_only,
                                    per_host_rare=not args.no_per_host_rare, beacon_min_net=args.beacon_min_net)
        model.save(args.model_dir)
        print(json.dumps(model.public_meta(), indent=2))
        return 0
    model = AnomalyModel.load(args.model_dir)
    print(json.dumps(evaluate_windows(model.score_events(events), events), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

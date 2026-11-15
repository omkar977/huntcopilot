"""In-memory fakes of Redis streams (consumer groups) and OpenSearch for ingestor unit tests."""
import json


class ResponseError(Exception):
    pass


class FakeRedis:
    def __init__(self):
        self.streams, self.groups, self.dlq_calls = {}, {}, []
        self._n = 0

    def xadd(self, name, fields, maxlen=None, approximate=True, **_):
        self._n += 1
        msg_id = f"{self._n:010d}-0"
        self.streams.setdefault(name, []).append((msg_id, dict(fields)))
        return msg_id

    def pipeline(self, transaction=True):
        outer = self

        class P:
            ops = []

            def xadd(self, *a, **k):
                self.ops.append((a, k))
                return self

            def execute(self):
                for a, k in self.ops:
                    outer.xadd(*a, **k)
                self.ops = []

        return P()

    def xlen(self, name):
        return len(self.streams.get(name, []))

    def xinfo_groups(self, name):
        return []

    def xgroup_create(self, name, group, id="0", mkstream=False):
        if name not in self.streams:
            if not mkstream:
                raise ResponseError("no stream")
            self.streams[name] = []
        if group in self.groups.setdefault(name, {}):
            raise ResponseError("BUSYGROUP Consumer Group name already exists")
        self.groups[name][group] = {"cursor": 0, "pending": {}}

    def xreadgroup(self, group, consumer, streams, count=None, block=None):
        (name, read_id), = streams.items()
        g = self.groups[name][group]
        entries = self.streams[name]
        if read_id == "0":
            mine = [(i, f) for i, (c, f) in g["pending"].items() if c == consumer]
            mine = mine[:count] if count else mine
            return [[name, mine]] if mine else []
        batch = entries[g["cursor"]:g["cursor"] + (count or len(entries))]
        g["cursor"] += len(batch)
        for msg_id, fields in batch:
            g["pending"][msg_id] = (consumer, fields)
        return [[name, list(batch)]] if batch else []

    def xack(self, name, group, *ids):
        for i in ids:
            self.groups[name][group]["pending"].pop(i, None)
        return len(ids)

    def xautoclaim(self, name, group, consumer, min_idle_time, start_id="0-0", count=None):
        g = self.groups[name][group]
        taken = [(i, f) for i, (c, f) in g["pending"].items() if c != consumer]
        for i, f in taken:
            g["pending"][i] = (consumer, f)
        return ["0-0", taken[:count] if count else taken, []]

    # helpers for assertions
    def pending(self, name, group):
        return self.groups[name][group]["pending"]

    def stream_fields(self, name):
        return [f for _, f in self.streams.get(name, [])]


class FakeIndices:
    def __init__(self):
        self.templates = {}

    def put_index_template(self, name, body):
        self.templates[name] = body


class FakeOpenSearch:
    def __init__(self):
        self.docs, self.indices = {}, FakeIndices()
        self.bulk_calls, self.fail_ids, self.raise_next = 0, {}, 0

    def bulk(self, body):
        self.bulk_calls += 1
        if self.raise_next:
            self.raise_next -= 1
            raise ConnectionError("opensearch down")
        items, errors = [], False
        for i in range(0, len(body), 2):
            meta, doc = body[i]["index"], body[i + 1]
            status = self.fail_ids.get(meta["_id"], 200)
            if status < 300:
                existed = (meta["_index"], meta["_id"]) in self.docs
                self.docs[(meta["_index"], meta["_id"])] = json.loads(json.dumps(doc))
                status = 200 if existed else 201
            else:
                errors = True
            items.append({"index": {"_index": meta["_index"], "_id": meta["_id"], "status": status}})
        return {"errors": errors, "items": items}

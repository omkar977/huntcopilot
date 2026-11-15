"""Minimal in-memory stand-in for the Redis calls the generator makes (no network in unit tests)."""


class FakePipeline:
    def __init__(self, client):
        self.client, self.ops = client, []

    def xadd(self, name, fields, maxlen=None, approximate=True):
        self.ops.append((name, fields, maxlen, approximate))
        return self

    def execute(self):
        for name, fields, maxlen, approximate in self.ops:
            self.client.xadd(name, fields, maxlen=maxlen, approximate=approximate)
        self.ops = []


class FakeRedis:
    def __init__(self, backlog=0):
        self.streams, self.calls, self.backlog_value = {}, [], backlog

    def xadd(self, name, fields, maxlen=None, approximate=True):
        self.streams.setdefault(name, []).append(fields)
        self.calls.append((maxlen, approximate))

    def pipeline(self, transaction=True):
        return FakePipeline(self)

    def xlen(self, name):
        return self.backlog_value or len(self.streams.get(name, []))

    def xinfo_groups(self, name):
        return []

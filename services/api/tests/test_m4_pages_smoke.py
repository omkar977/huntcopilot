"""Run dashboard pages 2, 4, 5 against a stub streamlit and a fake api_client (no browser needed)."""
import contextlib
import pathlib
import runpy
import sys
import types


PAGES = pathlib.Path(__file__).resolve().parents[2] / "dashboard" / "pages"


class Ctx:
    def __init__(self, owner=None):
        self.owner = owner

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __getattr__(self, name):
        if self.owner is not None:
            return getattr(self.owner, name)  # st.columns()[i].button(...) behaves like st.button(...)
        return lambda *a, **k: None


class State(dict):
    __getattr__ = dict.get


class StubStreamlit(types.ModuleType):
    def __init__(self, press=(), texts=None, checked=False):
        super().__init__("streamlit")
        self.press, self.texts, self.checked = set(press), texts or {}, checked
        self.session_state, self.calls = State(), []

    def __getattr__(self, name):
        def fn(*a, **k):
            self.calls.append((name, a, k))
            return None
        return fn

    def button(self, label, key=None, **k):
        return label in self.press or key in self.press

    def checkbox(self, *a, **k):
        return self.checked

    def text_input(self, label, value="", **k):
        return self.texts.get(label, value)

    def text_area(self, label, value="", **k):
        return self.texts.get(label, value)

    def selectbox(self, label, options, **k):
        return options[0]

    def columns(self, n, **k):
        return [Ctx(self) for _ in range(n if isinstance(n, int) else len(n))]

    def expander(self, *a, **k):
        return Ctx()

    def spinner(self, *a, **k):
        return Ctx()

    def stop(self):
        raise SystemExit

    def seen(self, name):
        return [c for c in self.calls if c[0] == name]


FINDING = {"finding_id": "f" * 40, "hosts": ["WS-03", "DB-01"], "rationale": "Confidence 87 of 100 (high).",
           "scores": {"confidence": 86.6}}
PLAN = {"plan_id": "p1", "hypothesis": "h", "source": "fallback", "template": "t", "expected_stages": ["execution"],
        "validation": {"ok": True, "errors": [], "warnings": ["w1"]},
        "steps": [{"step_id": "s1", "description": "d", "stage": "execution", "depends_on": [],
                   "query": {"filters": [{"field": "host", "op": "eq", "value": "x"}]}}]}
PROP = {"proposal_id": "q" * 32, "finding_id": "f" * 40, "action": "isolate_host", "target": "WS-03",
        "justification": "because", "status": "pending"}


def fake_client(log, fail=False):
    m = types.ModuleType("api_client")

    def rec(name, ret):
        def fn(*a, **k):
            log.append((name, a))
            if fail:
                raise RuntimeError("API down")
            return ret
        return fn

    for name, ret in {
        "create_hunt": PLAN,
        "run_hunt": {"run_id": "r" * 32, "status": "completed", "error": "",
                     "step_results": [{"step_id": "s1", "event_count": 1, "hosts": ["WS-03"], "duration_ms": 3}],
                     "findings": [FINDING]},
        "list_findings": {"items": [FINDING], "total": 1}, "list_proposals": {"items": [PROP], "total": 1},
        "approve_proposal": {"status": "executed", "result": "simulated"}, "reject_proposal": {"status": "rejected"},
        "verify_audit": {"ok": True, "first_bad_seq": None}, "get_state": {"host_state": []},
        "get_audit": {"items": []}, "export_case": "# Case", }.items():
        setattr(m, name, rec(name, ret))
    return m


@contextlib.contextmanager
def run_page(name, st_stub, client):
    saved = {k: sys.modules.get(k) for k in ("streamlit", "api_client")}
    sys.modules["streamlit"], sys.modules["api_client"] = st_stub, client
    try:
        try:
            runpy.run_path(str(PAGES / name), run_name="__page__")
        except SystemExit:
            pass
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def test_hunt_builder_generate_and_run():
    log = []
    st = StubStreamlit(press={"Generate plan"}, texts={"Hunt request": "Find lateral movement"})
    st.session_state["run"] = None
    with run_page("2_Hunt_Builder.py", st, fake_client(log)):
        pass
    assert ("create_hunt", ("Find lateral movement",)) in log and st.seen("warning")
    st2 = StubStreamlit(press={"Run hunt"})
    st2.session_state["plan"] = PLAN
    log2 = []
    with run_page("2_Hunt_Builder.py", st2, fake_client(log2)):
        pass
    assert log2 == [("run_hunt", ("p1",))] and st2.session_state["run"]["status"] == "completed"


def test_hunt_builder_survives_api_errors():
    st = StubStreamlit(press={"Generate plan"}, texts={"Hunt request": "Find lateral movement"})
    with run_page("2_Hunt_Builder.py", st, fake_client([], fail=True)):
        pass
    assert any("API down" in str(c[1]) for c in st.seen("error"))


def test_approvals_requires_name_and_confirmation():
    log = []
    st = StubStreamlit(press={"Approve"}, texts={"Approver name": ""}, checked=False)
    with run_page("4_Response_Approvals.py", st, fake_client(log)):
        pass
    assert not [c for c in log if c[0] == "approve_proposal"] and st.seen("warning")
    log2 = []
    st2 = StubStreamlit(press={"Approve"}, texts={"Approver name": "soc.lead"}, checked=True)
    with run_page("4_Response_Approvals.py", st2, fake_client(log2)):
        pass
    assert ("approve_proposal", ("q" * 32, "soc.lead", True)) in log2 and st2.seen("success")


def test_approvals_reject_and_api_down():
    log = []
    st = StubStreamlit(press={"Reject"}, texts={"Approver name": "soc.lead"})
    with run_page("4_Response_Approvals.py", st, fake_client(log)):
        pass
    assert any(c[0] == "reject_proposal" for c in log)
    st2 = StubStreamlit()
    with run_page("4_Response_Approvals.py", st2, fake_client([], fail=True)):
        pass
    assert st2.seen("error")


def test_case_export_offers_both_downloads():
    log = []
    st = StubStreamlit()
    with run_page("5_Case_Export.py", st, fake_client(log)):
        pass
    assert len(st.seen("download_button")) == 2
    assert ("export_case", ("f" * 40, "md")) in log


def test_missing_api_client_function_is_a_readable_error():
    m = types.ModuleType("api_client")
    st = StubStreamlit()
    with run_page("4_Response_Approvals.py", st, m):
        pass
    assert any("missing" in str(c[1]) for c in st.seen("error"))

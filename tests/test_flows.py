"""
tests/test_flows.py
Mail-flow graph: from one sending IP or domain, which recipients got mail and how many.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import QTableWidget

from app.dashboard import DashboardWindow
from app.graph_view import GraphPage
from core.correlation.flows import (
    MORE_PREFIX,
    NO_RECIPIENT,
    SENDER_PREFIX,
    build_flow_graph,
    build_flows,
    parse_recipient_node_id,
    recipient_node_id,
    recipients_of,
    sender_key,
)
from core.parser.models import AuthResults, HeaderInfo, ParsedEmail, ReceivedHop
from core.storage.database import Database
from core.storage.ingest import ingest_parsed_email


def _row(eid: int, ip: str = "", frm: str = "", to: str = "", cc: str = "", subject: str = "s") -> dict:
    return {"id": eid, "first_hop_ip": ip, "subject": subject, "filename": f"{eid}.eml", "first_seen": "t",
            "headers_json": json.dumps({"from_addr": frm, "to": to, "cc": cc, "subject": subject,
                                        "date": "Mon, 02 Nov 2026"})}


# ---------------------------------------------------------------------------
# Data rules
# ---------------------------------------------------------------------------

class TestRecipients:
    def test_to_and_cc_lowercased_unique_display_names_ignored(self) -> None:
        headers = {"to": 'Alice <Alice@Corp.com>, "Bob, B" <bob@corp.com>', "cc": "alice@corp.com, carol@corp.com"}
        assert recipients_of(headers) == ["alice@corp.com", "bob@corp.com", "carol@corp.com"]

    @pytest.mark.parametrize("to", ["", "undisclosed-recipients:;", "not an address", "@nolocal.com", "nodomain@"])
    def test_no_usable_address(self, to: str) -> None:
        assert recipients_of({"to": to}) == []


class TestSenderKey:
    def test_ip_mode_uses_first_external_hop(self) -> None:
        assert sender_key(_row(1, ip=" 198.51.100.7 "), "ip") == "198.51.100.7"
        assert sender_key(_row(1), "ip") is None

    def test_domain_mode_uses_the_real_from_address(self) -> None:
        spoof = _row(1, frm='"support@paypal.com" <x7@Mailer-XYZ.top>')
        assert sender_key(spoof, "domain") == "mailer-xyz.top"
        assert sender_key(_row(1, frm="no address"), "domain") is None
        assert sender_key(_row(1, frm="a@printer.local"), "domain") is None

    def test_unknown_mode(self) -> None:
        with pytest.raises(ValueError):
            sender_key(_row(1), "asn")
        with pytest.raises(ValueError):
            build_flows([], "asn")


class TestBuildFlows:
    def test_counts(self) -> None:
        rows = [
            _row(1, ip="1.1.1.1", to="a@x.com, b@x.com"),
            _row(2, ip="1.1.1.1", to="a@x.com", cc="a@x.com"),      # a@ counted once for this mail
            _row(3, ip="1.1.1.1", to="undisclosed-recipients:;"),
            _row(4, ip="2.2.2.2", to="a@x.com"),
            _row(5, to="a@x.com"),                                   # no sending IP
        ]
        s = build_flows(rows, "ip")
        assert [f.key for f in s.senders] == ["1.1.1.1", "2.2.2.2"]   # busiest first
        first = s.sender("1.1.1.1")
        assert first.mail_count == 3
        assert first.recipients == {"a@x.com": 2, "b@x.com": 1, NO_RECIPIENT: 1}
        assert first.recipient_count == 3
        assert (s.mails_total, s.mails_without_sender) == (5, 1)
        assert s.senders_for_recipient("a@x.com") == [("1.1.1.1", 2), ("2.2.2.2", 1)]
        assert s.senders_for_recipient("nobody@x.com") == []
        assert [m.id for m in first.mails] == [1, 2, 3]

    def test_ties_sorted_by_name_and_top(self) -> None:
        s = build_flows([_row(1, ip="9.9.9.9", to="a@x.com"), _row(2, ip="1.1.1.1", to="a@x.com")], "ip")
        assert [f.key for f in s.senders] == ["1.1.1.1", "9.9.9.9"]
        assert len(s.top(1)) == 1 and len(s.top(0)) == 2

    def test_domain_mode(self) -> None:
        rows = [_row(1, frm="x@evil.org", to="a@x.com"), _row(2, frm="y@EVIL.org", to="b@x.com")]
        s = build_flows(rows, "domain")
        assert [(f.key, f.mail_count) for f in s.senders] == [("evil.org", 2)]


# ---------------------------------------------------------------------------
# Graph structure
# ---------------------------------------------------------------------------

def _big_summary():
    rows = []
    eid = 0
    for i in range(10):                                    # sender i mails 10 + i recipients
        for r in range(10 + i):
            eid += 1
            rows.append(_row(eid, ip=f"10.0.{i}.1", to=f"user{r}@corp.com"))
    return build_flows(rows, "ip")


class TestFlowGraph:
    def test_overview_top_n_and_recipient_cap(self) -> None:
        g = build_flow_graph(_big_summary(), top_n=3, max_recipients=4)
        assert [s.key for s in g.senders] == ["10.0.9.1", "10.0.8.1", "10.0.7.1"]
        more = [n for n in g.nodes if n["id"].startswith(MORE_PREFIX)]
        assert len(more) == 3
        assert more[0]["label"].startswith("+15 more recipients")          # 19 recipients - 4 shown
        dashed = [e for e in g.edges if e["to"].startswith(MORE_PREFIX)]
        assert all(e["dashes"] for e in dashed) and dashed[0]["mails"] == 15

    def test_each_sender_gets_its_own_recipient_boxes(self) -> None:
        """No lines crossing between senders: a shared address appears under each sender."""
        g = build_flow_graph(_big_summary(), top_n=3, max_recipients=4)
        user0 = [n for n in g.nodes if n["id"].endswith("user0@corp.com")]
        assert len(user0) == 3
        for node in user0:
            sender, address = parse_recipient_node_id(node["id"])
            assert address == "user0@corp.com" and node["label"] == "user0@corp.com\n1 mail"
            assert [e["from"] for e in g.edges if e["to"] == node["id"]] == [SENDER_PREFIX + sender]
        assert g.recipient_count == 4                     # different addresses, not boxes

    def test_node_id_round_trip_and_control_characters(self) -> None:
        nid = recipient_node_id("198.51.100.7", "a@x.com")
        assert parse_recipient_node_id(nid) == ("198.51.100.7", "a@x.com")
        assert recipients_of({"to": "a\x1fb@x.com"}) == ["ab@x.com"]

    def test_recipient_box_shows_mail_count_and_arrow_width_grows(self) -> None:
        rows = [_row(i, ip="1.1.1.1", to="a@x.com") for i in range(1, 6)] + [_row(9, ip="1.1.1.1", to="b@x.com")]
        g = build_flow_graph(build_flows(rows, "ip"))
        a_id, b_id = recipient_node_id("1.1.1.1", "a@x.com"), recipient_node_id("1.1.1.1", "b@x.com")
        labels = {n["id"]: n["label"] for n in g.nodes}
        assert labels[a_id] == "a@x.com\n5 mails" and labels[b_id] == "b@x.com\n1 mail"
        mails = {e["to"]: e["mails"] for e in g.edges}
        assert mails == {a_id: 5, b_id: 1}
        widths = {e["to"]: e["width"] for e in g.edges}
        assert widths[a_id] > widths[b_id]
        assert all("label" not in e for e in g.edges)       # counts live in the boxes
        sender = next(n for n in g.nodes if n["id"] == SENDER_PREFIX + "1.1.1.1")
        assert sender["label"] == "1.1.1.1\n6 mails → 2 recipients"

    def test_focus_shows_one_sender_with_more_recipients(self) -> None:
        g = build_flow_graph(_big_summary(), focus="10.0.9.1", max_recipients=4)
        assert [s.key for s in g.senders] == ["10.0.9.1"]
        assert g.recipient_count == 19                                     # focus cap is higher (40)
        assert not any(n["id"].startswith(MORE_PREFIX) for n in g.nodes)
        assert build_flow_graph(_big_summary(), focus="not-there").nodes == []

    def test_levels_put_senders_left_and_recipients_right(self) -> None:
        g = build_flow_graph(_big_summary(), top_n=2)
        for n in g.nodes:
            assert n["level"] == (0 if n["id"].startswith(SENDER_PREFIX) else 1)

    def test_mail_supplied_text_is_escaped_in_tooltips(self) -> None:
        payload = '"<img src=x onerror=alert(1)>"@evil.com'
        g = build_flow_graph(build_flows([_row(1, ip="1.1.1.1", to=payload)], "ip"))
        html = g.to_html()
        assert "<img src=x" not in html
        assert all("<img" not in n["title"] for n in g.nodes)

    def test_html_has_readable_zoom_and_left_to_right_layout(self) -> None:
        html = build_flow_graph(_big_summary()).to_html()
        assert "window.mailintelFit" in html and '"direction": "LR"' in html
        assert "mailintel://node/" in html                                 # click bridge from finalize_vis_html


# ---------------------------------------------------------------------------
# Graph page
# ---------------------------------------------------------------------------

def _ingest(db: Database, eid: str, ip: str, frm: str, to: str, subject: str) -> None:
    hop = ReceivedHop(from_host="relay.example.net", by_host="mx.corp.com", from_ip=ip,
                      timestamp=None, raw="", is_external=True)
    ingest_parsed_email(ParsedEmail(
        filepath=f"/m/{eid}.eml", file_sha256=eid * 32,
        headers=HeaderInfo(from_addr=frm, to=to, subject=subject, date="Mon, 02 Nov 2026"),
        received_chain=[hop], first_external_hop=hop, auth_results=AuthResults(), body_plain="x",
    ), db)


@pytest.fixture
def flow_db(tmp_path: Path) -> Path:
    path = tmp_path / "flow.db"
    db = Database(path)
    _ingest(db, "a1", "198.51.100.7", "x@spam-a.org", "alice@corp.com, bob@corp.com", "Win now")
    _ingest(db, "a2", "198.51.100.7", "x@spam-a.org", "alice@corp.com", "Win again")
    _ingest(db, "a3", "198.51.100.7", "y@spam-a.org", "carol@corp.com", "Invoice")
    _ingest(db, "b1", "203.0.113.9", "z@spam-b.net", "alice@corp.com", "Hello")
    db.close()
    return path


def _drawer_tables(window: DashboardWindow) -> list[QTableWidget]:
    layout = window.graph_drawer_vbox
    widgets = [layout.itemAt(i).widget() for i in range(layout.count())]
    return [w for w in widgets if isinstance(w, QTableWidget)]


def _rows(table: QTableWidget) -> list[tuple[str, str]]:
    return [(table.item(r, 0).text(), table.item(r, 1).text()) for r in range(table.rowCount())]


class TestGraphPage:
    def _open(self, path: Path, qtbot) -> DashboardWindow:
        window = DashboardWindow(db_path=path)
        qtbot.addWidget(window)
        window.select_nav_button(2)
        return window

    def test_default_view_is_ip_to_recipients(self, flow_db: Path, qtbot) -> None:
        window = self._open(flow_db, qtbot)
        assert window.graph_view_combo.currentData() == "ip"
        assert "Top 2 of 2 sending IPs" in window.graph_stats_label.text()
        assert not window.graph_focus_combo.isHidden() and window.graph_campaign_combo.isHidden()
        items = [window.graph_focus_combo.itemText(i) for i in range(window.graph_focus_combo.count())]
        assert items[1].startswith("198.51.100.7") and "3 mails → 3 recipients" in items[1]

    def test_clicking_a_sender_lists_recipients_with_counts_and_its_mails(self, flow_db: Path, qtbot) -> None:
        window = self._open(flow_db, qtbot)
        window.on_graph_node_clicked(SENDER_PREFIX + "198.51.100.7")
        recipients, mails = _drawer_tables(window)
        assert _rows(recipients) == [("alice@corp.com", "2"), ("bob@corp.com", "1"), ("carol@corp.com", "1")]
        assert {r[0] for r in _rows(mails)} == {"Win now", "Win again", "Invoice"}

    def test_clicking_a_recipient_lists_who_mailed_it(self, flow_db: Path, qtbot) -> None:
        window = self._open(flow_db, qtbot)
        window.on_graph_node_clicked(recipient_node_id("203.0.113.9", "alice@corp.com"))
        (senders,) = _drawer_tables(window)
        assert _rows(senders) == [("198.51.100.7", "2"), ("203.0.113.9", "1")]

    def test_focus_on_one_ip(self, flow_db: Path, qtbot) -> None:
        window = self._open(flow_db, qtbot)
        window.graph_focus_combo.setCurrentIndex(window.graph_focus_combo.findData("203.0.113.9"))
        assert window.graph_stats_label.text().startswith("203.0.113.9: 1 mails → 1 recipients")

    def test_domain_view(self, flow_db: Path, qtbot) -> None:
        window = self._open(flow_db, qtbot)
        window.graph_view_combo.setCurrentIndex(window.graph_view_combo.findData("domain"))
        assert "sending domain" in window.graph_title_label.text()
        assert window.graph_focus_combo.findData("spam-a.org") > 0
        window.on_graph_node_clicked(SENDER_PREFIX + "spam-a.org")
        assert _rows(_drawer_tables(window)[0])[0] == ("alice@corp.com", "2")

    def test_limit_selector_redraws(self, flow_db: Path, qtbot) -> None:
        window = self._open(flow_db, qtbot)
        window.graph_limit_combo.setCurrentIndex(window.graph_limit_combo.findData(10))
        assert "of 2 sending IPs" in window.graph_stats_label.text()
        assert [window.graph_limit_combo.itemData(i) for i in range(window.graph_limit_combo.count())] == \
            [10, 20, 30, 50, 100]

    def test_old_network_view_still_available(self, flow_db: Path, qtbot) -> None:
        window = self._open(flow_db, qtbot)
        window.graph_view_combo.setCurrentIndex(window.graph_view_combo.findData("network"))
        assert "Active Graph:" in window.graph_stats_label.text()
        assert window.graph_focus_combo.isHidden() and not window.graph_campaign_combo.isHidden()

    def test_empty_database(self, tmp_path: Path, qtbot) -> None:
        empty = tmp_path / "e.db"
        Database(empty).close()
        window = self._open(empty, qtbot)
        assert "No emails ingested" in window.graph_stats_label.text()


# ---------------------------------------------------------------------------
# Real browser engine
# ---------------------------------------------------------------------------

def test_flow_page_loads_and_clicks_reach_qt(qtbot) -> None:
    html = build_flow_graph(_big_summary(), focus="10.0.9.1").to_html()
    view = QWebEngineView()
    page = GraphPage(view)
    view.setPage(page)
    view.resize(1200, 700)
    qtbot.addWidget(view)
    with qtbot.waitSignal(page.loadFinished, timeout=30_000):
        view.setHtml(html)
    qtbot.wait(600)                                              # initial zoom runs after 250 ms
    result: list = []
    page.runJavaScript("typeof window.mailintelFit + '|' + network.getScale()", result.append)
    qtbot.waitUntil(lambda: bool(result), timeout=10_000)
    kind, scale = result[0].split("|")
    assert kind == "function"
    assert float(scale) >= 0.84                                  # tall graph opens readable, not shrunk
    with qtbot.waitSignal(page.nodeSelected, timeout=10_000) as blocker:
        page.runJavaScript(f"network.body.emitter.emit('selectNode', {{nodes:['{SENDER_PREFIX}10.0.9.1']}});")
    assert blocker.args == [SENDER_PREFIX + "10.0.9.1"]

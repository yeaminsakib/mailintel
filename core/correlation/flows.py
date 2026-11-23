"""
core/correlation/flows.py
"Mail flow" view: for every sender, which recipient addresses got mail and how many.

A sender is either
* ``ip``     - the first external hop of the Received chain (the real sending server), or
* ``domain`` - the domain of the real From address (the display name is ignored, so
  ``"support@paypal.com" <x@evil.org>`` counts as ``evil.org``).

Recipients are the addresses in To and Cc.  A mail without any visible recipient
(e.g. ``undisclosed-recipients:;``) is counted under :data:`NO_RECIPIENT`, so the
numbers always add up.  Mails without a sending IP / From domain are counted in
:attr:`FlowSummary.mails_without_sender` instead of being dropped silently.

:func:`build_flow_graph` turns a summary into a left-to-right graph: senders on the
left, recipients on the right, one arrow per sender/recipient pair labelled with
the number of mails.
"""
from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from email.utils import getaddresses
from html import escape
from typing import Any

from pyvis.network import Network

from core.ioc.normalize import email_domain

from .graph_builder import finalize_vis_html

MODES: tuple[str, ...] = ("ip", "domain")

#: Recipient bucket for mails whose To/Cc show no address.
NO_RECIPIENT = "(no visible recipient)"

# Node id prefixes; the dashboard uses them to know what was clicked.
SENDER_PREFIX = "flow-sender:"
RECIPIENT_PREFIX = "flow-rcpt:"
MORE_PREFIX = "flow-more:"

#: Separates sender and address inside a recipient node id (each sender gets its own
#: recipient boxes).  Control characters are removed from addresses, so it cannot clash.
ID_SEPARATOR = "\x1f"


def recipient_node_id(sender: str, address: str) -> str:
    return f"{RECIPIENT_PREFIX}{sender}{ID_SEPARATOR}{address}"


def parse_recipient_node_id(node_id: str) -> tuple[str, str]:
    """``(sender, address)`` from a recipient node id."""
    sender, _, address = node_id[len(RECIPIENT_PREFIX):].partition(ID_SEPARATOR)
    return sender, address

COLORS: dict[str, str] = {
    "ip": "#3b82f6",
    "domain": "#a78bfa",
    "recipient": "#f59e0b",
    "more": "#64748b",
}


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MailRef:
    """Just enough about one mail to list it in the details panel."""

    id: int
    subject: str
    date: str
    filename: str


@dataclass
class SenderFlow:
    """All mail from one sending IP or domain."""

    key: str
    mails: list[MailRef] = field(default_factory=list)
    recipients: Counter[str] = field(default_factory=Counter)   # address -> number of mails

    @property
    def mail_count(self) -> int:
        return len(self.mails)

    @property
    def recipient_count(self) -> int:
        return len(self.recipients)

    def ranked_recipients(self) -> list[tuple[str, int]]:
        """``(address, mails)`` with most mails first; ties in alphabetical order (stable display)."""
        return sorted(self.recipients.items(), key=lambda item: (-item[1], item[0]))


@dataclass
class FlowSummary:
    """Senders ordered by number of mails (most first)."""

    mode: str
    senders: list[SenderFlow]
    mails_total: int
    mails_without_sender: int

    def top(self, n: int) -> list[SenderFlow]:
        """The *n* busiest senders (all of them when ``n <= 0``)."""
        return self.senders[:n] if n > 0 else list(self.senders)

    def sender(self, key: str) -> SenderFlow | None:
        return next((s for s in self.senders if s.key == key), None)

    def senders_for_recipient(self, address: str) -> list[tuple[str, int]]:
        """``(sender, mails)`` pairs for one recipient, most mails first."""
        pairs = [(s.key, s.recipients[address]) for s in self.senders if s.recipients.get(address)]
        return sorted(pairs, key=lambda p: (-p[1], p[0]))


def _headers(email: dict[str, Any]) -> dict[str, Any]:
    value = email.get("headers_json")
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def recipients_of(headers: dict[str, Any]) -> list[str]:
    """Unique, lower-cased addresses from To and Cc (display names ignored)."""
    seen: set[str] = set()
    result: list[str] = []
    for _name, addr in getaddresses([str(headers.get("to") or ""), str(headers.get("cc") or "")]):
        addr = "".join(ch for ch in addr if ch.isprintable()).strip().strip("<>").lower()
        local, _, domain = addr.rpartition("@")
        if not local or not domain:
            continue
        if addr not in seen:
            seen.add(addr)
            result.append(addr)
    return result


def sender_key(email: dict[str, Any], mode: str) -> str | None:
    """The sending IP or the sending domain of a stored mail, or ``None`` if unknown."""
    if mode == "ip":
        ip = str(email.get("first_hop_ip") or "").strip()
        return ip or None
    if mode == "domain":
        from_value = _headers(email).get("from_addr") or email.get("from_addr") or ""
        for _name, addr in getaddresses([str(from_value)]):
            domain = email_domain(addr)
            if domain:
                return domain
        return None
    raise ValueError(f"unknown flow mode: {mode!r} (use one of {MODES})")


def build_flows(emails: list[dict[str, Any]], mode: str) -> FlowSummary:
    """Group stored mails by sender and count mails per recipient."""
    if mode not in MODES:
        raise ValueError(f"unknown flow mode: {mode!r} (use one of {MODES})")
    by_key: dict[str, SenderFlow] = {}
    without_sender = 0
    for email in emails:
        key = sender_key(email, mode)
        if key is None:
            without_sender += 1
            continue
        flow = by_key.setdefault(key, SenderFlow(key))
        headers = _headers(email)
        flow.mails.append(MailRef(
            id=int(email["id"]),
            subject=str(email.get("subject") or headers.get("subject") or ""),
            date=str(headers.get("date") or email.get("first_seen") or ""),
            filename=str(email.get("filename") or ""),
        ))
        flow.recipients.update(recipients_of(headers) or [NO_RECIPIENT])   # each recipient once per mail
    senders = sorted(by_key.values(), key=lambda f: (-f.mail_count, f.key))
    return FlowSummary(mode=mode, senders=senders, mails_total=len(emails), mails_without_sender=without_sender)


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


@dataclass
class FlowGraph:
    """Nodes and edges of the mail-flow graph (vis-network format)."""

    mode: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    senders: list[SenderFlow]

    @property
    def recipient_count(self) -> int:
        """Different recipient addresses shown (an address can appear under several senders)."""
        return len({parse_recipient_node_id(n["id"])[1] for n in self.nodes
                    if n["id"].startswith(RECIPIENT_PREFIX)})

    def to_html(self) -> str:
        """Self-contained HTML page (dark theme, click bridge) for the Graph page."""
        net = Network(height="100%", width="100%", bgcolor="#15181e", font_color="#f1f5f9",
                      cdn_resources="in_line", directed=True)
        for node in self.nodes:
            net.add_node(node["id"], **{k: v for k, v in node.items() if k != "id"})
        for edge in self.edges:
            net.add_edge(edge["from"], edge["to"], **{k: v for k, v in edge.items() if k not in ("from", "to")})
        net.set_options(json.dumps(_VIS_OPTIONS))
        html = finalize_vis_html(net.generate_html())
        return html.replace("</head>", _READABLE_ZOOM + "</head>", 1)


def _box(color: str) -> dict[str, Any]:
    return {
        "background": "#1e2533",
        "border": color,
        "highlight": {"background": "#273246", "border": "#ffffff"},
        "hover": {"background": "#273246", "border": color},
    }


def build_flow_graph(
    summary: FlowSummary,
    *,
    top_n: int = 20,
    focus: str | None = None,
    max_recipients: int = 6,
    max_recipients_focus: int = 40,
) -> FlowGraph:
    """Senders (left) -> recipients (right); each recipient box shows its number of mails.

    * ``focus`` shows one sender only, with up to ``max_recipients_focus`` recipients.
    * Otherwise the ``top_n`` busiest senders are shown with up to ``max_recipients``
      recipients each; the rest of a sender's recipients are folded into one
      "+N more" box so the picture stays readable.
    * Every sender gets its own fan of recipient boxes (no lines crossing between
      senders).  Which senders mailed one address is shown when it is clicked.
    * Arrow thickness grows with the number of mails; the count itself is written in
      the recipient box (labels on crowded arrows were hard to match to an arrow).
    """
    if focus is not None:
        chosen = summary.sender(focus)
        senders = [chosen] if chosen else []
        cap = max_recipients_focus
    else:
        senders = summary.top(top_n)
        cap = max_recipients

    sender_color = COLORS.get(summary.mode, COLORS["ip"])
    what = "IP" if summary.mode == "ip" else "domain"
    max_pair = max((s.recipients.most_common(1)[0][1] for s in senders if s.recipients), default=1)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    def edge(src: str, dst: str, count: int, tip: str, dashed: bool = False) -> dict[str, Any]:
        return {
            "from": src, "to": dst, "title": escape(tip), "mails": count,
            "width": round(1.5 + 6.5 * min(count, max_pair) / max_pair, 2),
            "dashes": dashed,
        }

    for flow in senders:
        sid = SENDER_PREFIX + flow.key
        nodes.append({
            "id": sid,
            "label": f"{flow.key}\n{_plural(flow.mail_count, 'mail')} → {_plural(flow.recipient_count, 'recipient')}",
            "title": escape(f"Sending {what} {flow.key}: {_plural(flow.mail_count, 'mail')} "
                            f"to {_plural(flow.recipient_count, 'recipient')}. Click for the list."),
            "level": 0, "shape": "box", "color": _box(sender_color),
            "borderWidth": 3, "font": {"color": "#f8fafc", "size": 15, "face": "Consolas, monospace"},
        })
        ranked = flow.ranked_recipients()
        shown, rest = ranked[:cap], ranked[cap:]
        for address, count in shown:
            rid = recipient_node_id(flow.key, address)
            nodes.append({
                "id": rid,
                "label": f"{address}\n{_plural(count, 'mail')}",
                "title": escape(f"{address} received {_plural(count, 'mail')} from {flow.key}. "
                                f"Click to see every sender of this address."),
                "level": 1, "shape": "box",
                "color": _box(COLORS["more"] if address == NO_RECIPIENT else COLORS["recipient"]),
                "font": {"color": "#f1f5f9", "size": 13, "face": "Consolas, monospace"},
            })
            edges.append(edge(sid, rid, count, f"{flow.key} → {address}: {_plural(count, 'mail')}"))
        if rest:
            mid = MORE_PREFIX + flow.key
            rest_mails = sum(c for _, c in rest)
            nodes.append({
                "id": mid,
                "label": f"+{len(rest)} more recipients\n{_plural(rest_mails, 'mail')}",
                "title": escape(f"{len(rest)} further recipients of {flow.key}. Click the sender for the full list."),
                "level": 1, "shape": "box", "color": _box(COLORS["more"]),
                "font": {"color": "#94a3b8", "size": 12},
            })
            edges.append(edge(sid, mid, rest_mails, f"{flow.key} → {len(rest)} more recipients", dashed=True))

    return FlowGraph(mode=summary.mode, nodes=nodes, edges=edges, senders=senders)


_VIS_OPTIONS: dict[str, Any] = {
    "layout": {
        "hierarchical": {
            "enabled": True, "direction": "LR", "sortMethod": "directed",
            "levelSeparation": 420, "nodeSpacing": 64, "treeSpacing": 150,
            "blockShifting": True, "edgeMinimization": True, "parentCentralization": True,
        },
    },
    "physics": {"enabled": False},
    "interaction": {"hover": True, "tooltipDelay": 120, "zoomView": True, "dragView": True,
                    "dragNodes": True, "multiselect": False},
    "nodes": {"shape": "box", "margin": 10, "borderWidth": 2,
              "font": {"color": "#f1f5f9", "size": 13, "face": "Segoe UI, sans-serif"}},
    "edges": {
        "arrows": {"to": {"enabled": True, "scaleFactor": 0.6}},
        "smooth": {"enabled": True, "type": "cubicBezier", "forceDirection": "horizontal", "roundness": 0.45},
        "color": {"color": "rgba(148, 163, 184, 0.55)", "highlight": "#00f0ff", "hover": "#38bdf8"},
        "font": {"color": "#f8fafc", "size": 13, "strokeWidth": 5, "strokeColor": "#15181e", "align": "middle"},
    },
}

#: Zoom used when the whole graph would not fit at a readable size: instead of
#: shrinking everything to specks, open at this scale at the top of the graph and
#: let the analyst scroll / drag down.  Called on load and on resize through the
#: ``window.mailintelFit`` hook of :func:`finalize_vis_html`.
READABLE_SCALE = 0.85

_READABLE_ZOOM = """<script>
window.mailintelFit = function () {
    if (typeof network === "undefined" || !network) { return; }
    network.fit();
    if (network.getScale() >= __SCALE__) { return; }
    var pos = network.getPositions(), minX = Infinity, maxX = -Infinity, minY = Infinity;
    for (var id in pos) {
        var p = pos[id];
        if (p.x < minX) { minX = p.x; }
        if (p.x > maxX) { maxX = p.x; }
        if (p.y < minY) { minY = p.y; }
    }
    var height = (network.body && network.body.container && network.body.container.clientHeight) || 800;
    network.moveTo({position: {x: (minX + maxX) / 2, y: minY + (height / 2) / __SCALE__ - 60},
                    scale: __SCALE__});
};
</script>""".replace("__SCALE__", str(READABLE_SCALE))

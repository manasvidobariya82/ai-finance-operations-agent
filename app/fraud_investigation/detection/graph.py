"""Entity graph: customers, accounts, devices, IPs, beneficiaries and shared identity attributes,
linked by who-used-what. Surfaces coordinated fraud that per-transaction models miss (one device
behind many accounts, one beneficiary collecting from many victims).

An in-memory networkx graph rebuilt from SQL aggregates - fine for a prototype-sized dataset. A
production deployment would keep this in a graph database (e.g. Neo4j) and run the same queries
(k-hop expansion, shortest paths, community detection) there.
"""
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set

import networkx as nx
from networkx.algorithms.community import louvain_communities
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.fraud_investigation import models

# Nodes with more links than this are shared infrastructure (or a popular payee); traversal stops
# at them so they don't connect every customer to every other.
HUB_DEGREE = 30
MAX_SUBGRAPH_NODES = 45


def node_id(kind: str, key: str) -> str:
    return f"{kind}:{key}"


class EntityGraph:
    def __init__(self, graph: nx.Graph, excluded_shared_ips: int = 0):
        self.g = graph
        self.excluded_shared_ips = excluded_shared_ips

    # --- construction --------------------------------------------------------------------------

    @classmethod
    def build(cls, db: Session) -> "EntityGraph":
        g = nx.Graph()
        shared_ips = {
            ip for (ip,) in db.query(models.IpReputation.ip_address).filter(models.IpReputation.usage_type == "mobile_cgnat")
        }

        customers = db.query(models.Customer).all()
        for c in customers:
            g.add_node(node_id("customer", c.id), kind="customer", label=c.full_name, ref=c.id, kyc_status=c.kyc_status)
        account_by_number = {}
        for a in db.query(models.Account).all():
            nid = node_id("account", a.id)
            g.add_node(nid, kind="account", label=f"{a.id} ••{a.account_number[-4:]}", ref=a.id, status=a.status)
            g.add_edge(node_id("customer", a.customer_id), nid, relation="owns")
            account_by_number[a.account_number] = nid

        # Identity attributes only become nodes when two or more customers share them.
        for attr in ("phone", "email", "address"):
            holders = defaultdict(list)
            for c in customers:
                value = getattr(c, attr)
                if value:
                    holders[value.strip().lower()].append(c.id)
            for value, ids in holders.items():
                if len(ids) > 1:
                    nid = node_id(attr, value)
                    g.add_node(nid, kind=attr, label=value, ref=value)
                    for cid in ids:
                        g.add_edge(node_id("customer", cid), nid, relation=f"shares_{attr}")

        devices = {d.id: d for d in db.query(models.Device).all()}
        usage: Dict[tuple, dict] = {}
        for table in (models.Transaction, models.AccountEvent):
            for kind, column in (("device", table.device_id), ("ip", table.ip_address)):
                rows = (
                    db.query(table.customer_id, column, func.count(), func.min(table.timestamp), func.max(table.timestamp))
                    .filter(column.isnot(None))
                    .group_by(table.customer_id, column)
                )
                for customer_id, key, count, first, last in rows:
                    entry = usage.setdefault((customer_id, kind, key), {"count": 0, "first": first, "last": last})
                    entry["count"] += count
                    entry["first"] = min(entry["first"], first)
                    entry["last"] = max(entry["last"], last)
        for (customer_id, kind, key), stats in usage.items():
            if kind == "ip" and key in shared_ips:
                continue
            nid = node_id(kind, key)
            if nid not in g:
                label = key
                if kind == "device" and key in devices and devices[key].model:
                    label = f"{devices[key].model} ({key})"
                g.add_node(nid, kind=kind, label=label, ref=key)
            g.add_edge(
                node_id("customer", customer_id), nid, relation=f"uses_{kind}", count=stats["count"],
                first_seen=stats["first"].isoformat(), last_seen=stats["last"].isoformat(),
            )

        counterparties = {c.id: c for c in db.query(models.Counterparty).filter(models.Counterparty.kind == "beneficiary")}
        payments = (
            db.query(models.Transaction.account_id, models.Transaction.counterparty_id, func.count(), func.sum(models.Transaction.amount))
            .filter(models.Transaction.counterparty_id.in_(list(counterparties)))
            .group_by(models.Transaction.account_id, models.Transaction.counterparty_id)
        )
        for account_id, counterparty_id, count, total in payments:
            nid = node_id("beneficiary", counterparty_id)
            if nid not in g:
                cp = counterparties[counterparty_id]
                g.add_node(nid, kind="beneficiary", label=f"{cp.name} ••{(cp.account_number or '')[-4:]}", ref=cp.id)
                # Entity resolution: an external beneficiary that is really one of our own accounts.
                if cp.account_number in account_by_number:
                    g.add_edge(nid, account_by_number[cp.account_number], relation="same_account_number")
            g.add_edge(node_id("account", account_id), nid, relation="pays", count=count, amount=round(total or 0, 2))

        graph = cls(g, excluded_shared_ips=len(shared_ips))
        graph._mark_taint(db)
        return graph

    def _mark_taint(self, db: Session) -> None:
        """Flag instruments used in confirmed fraud (devices, IPs, beneficiaries) and blocklisted
        entities. Victims' own customer nodes are deliberately not tainted."""
        fraud_rows = (
            db.query(models.Transaction.device_id, models.Transaction.ip_address, models.Transaction.counterparty_id)
            .filter(models.Transaction.is_fraud.is_(True))
            .all()
        )
        for device_id, ip, counterparty_id in fraud_rows:
            for nid in (
                device_id and node_id("device", device_id),
                ip and node_id("ip", ip),
                counterparty_id and node_id("beneficiary", counterparty_id),
            ):
                if nid and nid in self.g:
                    self.g.nodes[nid]["tainted"] = True
                    self.g.nodes[nid]["taint_reason"] = "used in confirmed fraud"

        for entry in db.query(models.WatchlistEntry).filter(models.WatchlistEntry.list_name == "internal_blocklist"):
            targets: List[str] = []
            if entry.entity_type in ("device", "ip"):
                targets = [node_id(entry.entity_type, entry.value)]
            elif entry.entity_type == "account_number":
                targets = [
                    node_id("beneficiary", cp.id)
                    for cp in db.query(models.Counterparty).filter(models.Counterparty.account_number == entry.value)
                ]
            for nid in targets:
                if nid in self.g:
                    self.g.nodes[nid]["tainted"] = True
                    self.g.nodes[nid]["taint_reason"] = f"internal blocklist: {entry.reason or 'listed'}"

    # --- queries -------------------------------------------------------------------------------

    def is_hub(self, nid: str) -> bool:
        return self.g.degree(nid) > HUB_DEGREE

    def neighborhood(self, start: str, max_hops: int) -> Dict[str, int]:
        """BFS distances from `start`, not expanding through hub nodes."""
        if start not in self.g:
            return {}
        dist = {start: 0}
        frontier = [start]
        for hop in range(1, max_hops + 1):
            nxt = []
            for node in frontier:
                if node != start and self.is_hub(node):
                    continue
                for nb in self.g.neighbors(node):
                    if nb not in dist:
                        dist[nb] = hop
                        nxt.append(nb)
            frontier = nxt
        return dist

    def customers_of(self, nid: str) -> Set[str]:
        """Customers connected to an entity directly, or (for beneficiaries) via a paying account."""
        if nid not in self.g:
            return set()
        owners: Set[str] = set()
        for nb in self.g.neighbors(nid):
            if self.g.nodes[nb]["kind"] == "customer":
                owners.add(nb)
            elif self.g.nodes[nb]["kind"] == "account":
                owners.update(n for n in self.g.neighbors(nb) if self.g.nodes[n]["kind"] == "customer")
        return owners

    def transaction_risk(self, customer_id: str, device_id: Optional[str], ip: Optional[str], counterparty_id: Optional[str]) -> dict:
        """Graph risk component (0-1) for the entities one transaction touches."""
        me = node_id("customer", customer_id)
        factors = []
        entities = [
            ("device", device_id and node_id("device", device_id)),
            ("ip", ip and node_id("ip", ip)),
            ("beneficiary", counterparty_id and node_id("beneficiary", counterparty_id)),
        ]
        for kind, nid in entities:
            if not nid or nid not in self.g:
                continue
            data = self.g.nodes[nid]
            if data.get("tainted"):
                factors.append({"factor": f"{kind} {data['ref']} {data['taint_reason']}", "score": 0.6 if kind == "ip" else 0.8})
            others = len(self.customers_of(nid) - {me})
            if others >= 3:
                factors.append({"factor": f"{kind} {data['ref']} linked to {others} other customers", "score": 0.5})
            elif others >= 1 and kind != "ip":
                factors.append({"factor": f"{kind} {data['ref']} linked to {others} other customer(s)", "score": 0.25})
            if kind == "beneficiary":
                # Entity resolution + one more hop: the beneficiary is one of our own accounts whose
                # owner is connected to known-fraud instruments.
                for nb in self.g.neighbors(nid):
                    if self.g.nodes[nb]["kind"] != "account":
                        continue
                    owner = next((n for n in self.g.neighbors(nb) if self.g.nodes[n]["kind"] == "customer"), None)
                    if owner and owner != me and self._touches_taint(owner):
                        factors.append(
                            {"factor": f"beneficiary is account {self.g.nodes[nb]['ref']}, whose owner is linked to known fraud", "score": 0.6}
                        )
                        break
        remaining = 1.0
        for f in factors:
            remaining *= 1 - f["score"]
        return {"score": round(1 - remaining, 3), "factors": factors}

    def _touches_taint(self, customer_nid: str) -> bool:
        for nb in self.g.neighbors(customer_nid):
            if self.g.nodes[nb].get("tainted"):
                return True
            if self.g.nodes[nb]["kind"] == "account":
                if any(self.g.nodes[b].get("tainted") for b in self.g.neighbors(nb)):
                    return True
        return False

    def investigate(self, customer_id: str, max_hops: int, focus: Iterable[Optional[str]] = ()) -> dict:
        """Ego-network analysis for the graph agent: linked entities, paths, taint, communities."""
        me = node_id("customer", customer_id)
        dist = self.neighborhood(me, max_hops)
        if not dist:
            return {"available": False}
        sub = self.g.subgraph(dist)

        related_customers = []
        for nid, hops in sorted(dist.items(), key=lambda kv: kv[1]):
            if nid == me or self.g.nodes[nid]["kind"] != "customer":
                continue
            path = nx.shortest_path(sub, me, nid)
            related_customers.append(
                {
                    "customer_id": self.g.nodes[nid]["ref"],
                    "name": self.g.nodes[nid]["label"],
                    "hops": hops,
                    "path": [self._describe(n) for n in path],
                    "via": self.g.nodes[path[1]]["kind"] if len(path) > 2 else "direct",
                    "touches_known_fraud": self._touches_taint(nid),
                }
            )

        tainted = [
            {"node": nid, **self._describe(nid), "hops": hops, "reason": self.g.nodes[nid]["taint_reason"]}
            for nid, hops in dist.items()
            if self.g.nodes[nid].get("tainted")
        ]
        shared = []
        for nb in self.g.neighbors(me):
            kind = self.g.nodes[nb]["kind"]
            if kind in ("device", "ip", "phone", "email", "address"):
                others = [n for n in self.g.neighbors(nb) if n != me and self.g.nodes[n]["kind"] == "customer"]
                if others:
                    shared.append({**self._describe(nb), "shared_with": [self.g.nodes[o]["ref"] for o in others]})

        community = self._community(sub, me)
        counts = defaultdict(int)
        for nid in dist:
            if nid != me:
                counts[self.g.nodes[nid]["kind"]] += 1

        return {
            "available": True,
            "max_hops": max_hops,
            "entity_counts": dict(counts),
            "related_customers": related_customers,
            "tainted_entities": sorted(tainted, key=lambda t: t["hops"]),
            "shared_attributes": shared,
            "community": community,
            "excluded_shared_ips": self.excluded_shared_ips,
            "subgraph": self._render(sub, me, dist, {f for f in focus if f}),
        }

    def _community(self, sub: nx.Graph, me: str) -> dict:
        if sub.number_of_nodes() < 3:
            return {"size": sub.number_of_nodes(), "customers": 1, "tainted": 0}
        for members in louvain_communities(sub, seed=7):
            if me in members:
                customers = [m for m in members if self.g.nodes[m]["kind"] == "customer"]
                tainted = [m for m in members if self.g.nodes[m].get("tainted")]
                return {
                    "size": len(members),
                    "customers": len(customers),
                    "customer_ids": sorted(self.g.nodes[c]["ref"] for c in customers),
                    "tainted": len(tainted),
                }
        return {"size": 1, "customers": 1, "tainted": 0}

    def _describe(self, nid: str) -> dict:
        data = self.g.nodes[nid]
        return {"id": nid, "kind": data["kind"], "ref": data["ref"], "label": data["label"], "tainted": bool(data.get("tainted"))}

    def _render(self, sub: nx.Graph, me: str, dist: Dict[str, int], focus: Set[str]) -> dict:
        """Pick the most informative nodes (focal customer, transaction entities, taint, other
        customers, then nearest first) and lay them out for the case UI."""

        def priority(nid):
            data = self.g.nodes[nid]
            return (
                nid != me,
                nid not in focus,
                not data.get("tainted"),
                data["kind"] != "customer",
                dist[nid],
            )

        keep = sorted(dist, key=priority)[:MAX_SUBGRAPH_NODES]
        view = sub.subgraph(keep)
        # Keep only the component containing the focal customer so the picture is connected.
        view = view.subgraph(nx.node_connected_component(view, me)) if me in view else view
        positions = nx.spring_layout(view, seed=7, k=1.2 / max(1, len(view)) ** 0.5) if len(view) > 1 else {me: (0.0, 0.0)}
        xs = [p[0] for p in positions.values()] or [0]
        ys = [p[1] for p in positions.values()] or [0]
        span_x = (max(xs) - min(xs)) or 1
        span_y = (max(ys) - min(ys)) or 1

        nodes = []
        for nid in view.nodes:
            x, y = positions[nid]
            nodes.append(
                {
                    **self._describe(nid),
                    "hops": dist[nid],
                    "focal": nid == me,
                    "in_transaction": nid in focus,
                    "x": round((x - min(xs)) / span_x, 4),
                    "y": round((y - min(ys)) / span_y, 4),
                }
            )
        edges = [{"source": a, "target": b, "relation": d.get("relation")} for a, b, d in view.edges(data=True)]
        return {"nodes": nodes, "edges": edges, "truncated": len(dist) > len(nodes)}

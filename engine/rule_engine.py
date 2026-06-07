"""
WhoApp — Antigravity Rule Engine
Evaluates enriched flow events against YAML detection rules.
Supports operators: ==, !=, IN, NOT IN, >=, <=, BETWEEN, AND, OR
"""
import os
import re
import yaml
import logging
from datetime import datetime, timezone
from typing import Any, List, Dict, Optional

log = logging.getLogger(__name__)

RULES_PATH = os.getenv("RULES_PATH", "/app/rules/whoapp_rules.yaml")


def _get_field(event: dict, field_path: str) -> Any:
    """Navigate dot-notation field paths into the event dict."""
    # Map DSL field names to event dict keys
    mapping = {
        "app.name":           lambda e: e.get("app", {}).get("app_name"),
        "app.category":       lambda e: e.get("app", {}).get("app_category"),
        "app.risk_score":     lambda e: e.get("app", {}).get("app_risk_score", 0),
        "identity.user":      lambda e: e.get("identity", {}).get("user"),
        "identity.device_type": lambda e: e.get("identity", {}).get("device_type"),
        "identity.manufacturer": lambda e: e.get("identity", {}).get("manufacturer"),
        "network.direction":  lambda e: e.get("network_direction"),
        "time.hour_of_day":   lambda e: datetime.now(timezone.utc).hour,
        "time.is_weekend":    lambda e: datetime.now(timezone.utc).weekday() >= 5,
        "flow.byte_count":    lambda e: e.get("byte_count", 0),
        "flow.dst_port":      lambda e: int(e.get("dst_port") or 0),
        "flow.src_port":      lambda e: int(e.get("src_port") or 0),
        "flow.protocol":      lambda e: e.get("protocol"),
    }
    if field_path in mapping:
        return mapping[field_path](event)
    # Fallback: direct dict traversal
    parts = field_path.split(".")
    val = event
    for p in parts:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            return None
    return val


def _evaluate_condition(event: dict, cond: dict) -> bool:
    field = cond.get("field", "")
    op = cond.get("op", "==")
    expected = cond.get("value")
    actual = _get_field(event, field)

    if actual is None:
        return False

    try:
        if op == "==":
            return str(actual).lower() == str(expected).lower()
        elif op == "!=":
            return str(actual).lower() != str(expected).lower()
        elif op == "IN":
            return str(actual).lower() in [str(v).lower() for v in expected]
        elif op == "NOT IN":
            return str(actual).lower() not in [str(v).lower() for v in expected]
        elif op == ">=":
            return float(actual) >= float(expected)
        elif op == "<=":
            return float(actual) <= float(expected)
        elif op == ">":
            return float(actual) > float(expected)
        elif op == "<":
            return float(actual) < float(expected)
        elif op == "BETWEEN":
            lo, hi = float(expected[0]), float(expected[1])
            val = float(actual)
            # Handle wrap-around (e.g., 22–6 spanning midnight)
            if lo <= hi:
                return lo <= val <= hi
            else:
                return val >= lo or val <= hi
        else:
            log.warning("Unknown operator: %s", op)
            return False
    except (TypeError, ValueError) as e:
        log.debug("Condition eval error: %s", e)
        return False


def _evaluate_rule(event: dict, rule: dict) -> bool:
    """Return True if the event matches this rule's condition block."""
    conditions = rule.get("conditions", {})
    if "all" in conditions:
        return all(_evaluate_condition(event, c) for c in conditions["all"])
    elif "any" in conditions:
        return any(_evaluate_condition(event, c) for c in conditions["any"])
    return False


class RuleEngine:
    def __init__(self, rules_path: str = RULES_PATH):
        self.rules: List[dict] = []
        self._load_rules(rules_path)

    def _load_rules(self, path: str):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            self.rules = data.get("rules", [])
            log.info("Loaded %d detection rules from %s", len(self.rules), path)
        except Exception as e:
            log.error("Failed to load rules: %s", e)

    def evaluate(self, event: dict) -> List[dict]:
        """
        Evaluate all rules against an event.
        Returns list of triggered alert dicts.
        """
        alerts = []
        for rule in self.rules:
            if _evaluate_rule(event, rule):
                alert = {
                    "rule_name": rule["name"],
                    "description": rule.get("description", ""),
                    "severity": rule.get("severity", "Info"),
                    "tags": rule.get("tags", []),
                    "event": {
                        "src_ip": event.get("src_ip"),
                        "dst_ip": event.get("dst_ip"),
                        "dst_port": event.get("dst_port"),
                        "protocol": event.get("protocol"),
                        "app_name": event.get("app", {}).get("app_name"),
                        "app_category": event.get("app", {}).get("app_category"),
                        "risk_score": event.get("app", {}).get("app_risk_score"),
                        "user": event.get("identity", {}).get("user"),
                        "device_type": event.get("identity", {}).get("device_type"),
                        "manufacturer": event.get("identity", {}).get("manufacturer"),
                        "hostname": event.get("identity", {}).get("hostname"),
                        "tls_sni": event.get("tls_sni"),
                        "ja3": event.get("ja3"),
                        "byte_count": event.get("byte_count", 0),
                        "flow_id": event.get("flow_id"),
                    },
                    "ts": datetime.now(timezone.utc).isoformat(),
                }
                alerts.append(alert)
        return alerts

"""
WhoApp — Alert Emitter + Engine Main Loop
Consumes enriched flows from Redis stream, evaluates rules,
writes alerts to Redis pub/sub and InfluxDB.
"""
import os
import json
import time
import logging
from datetime import datetime, timezone

import redis
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

from rule_engine import RuleEngine

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [ENGINE] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_URL      = os.getenv("REDIS_URL", "redis://localhost:6379")
INFLUX_URL     = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN   = os.getenv("INFLUX_TOKEN", "whoapp-super-secret-token")
INFLUX_ORG     = os.getenv("INFLUX_ORG", "whoapp")
INFLUX_BUCKET  = os.getenv("INFLUX_BUCKET", "network_flows")
RULES_PATH     = os.getenv("RULES_PATH", "/app/rules/whoapp_rules.yaml")

ENRICHED_STREAM = "flows:enriched"
ALERTS_CHANNEL  = "alerts"
CONSUMER_GROUP  = "engine-group"
CONSUMER_NAME   = "engine-1"

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def setup_redis_group(r: redis.Redis):
    try:
        r.xgroup_create(ENRICHED_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def write_alert_to_influx(write_api, alert: dict):
    try:
        p = (
            Point("alert")
            .tag("rule_name", alert["rule_name"])
            .tag("severity", alert["severity"])
            .tag("user", alert["event"].get("user", "unknown"))
            .tag("app_name", alert["event"].get("app_name", "unknown"))
            .tag("device_type", alert["event"].get("device_type", "unknown"))
            .field("risk_score", float(alert["event"].get("risk_score") or 0))
            .field("byte_count", float(alert["event"].get("byte_count") or 0))
            .field("tags", ",".join(alert.get("tags", [])))
            .time(datetime.now(timezone.utc), WritePrecision.NANOSECONDS)
        )
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)
    except Exception as e:
        log.error("InfluxDB write error: %s", e)


def write_flow_to_influx(write_api, flow: dict):
    try:
        p = (
            Point("flow")
            .tag("src_ip", flow.get("src_ip", ""))
            .tag("dst_ip", flow.get("dst_ip", ""))
            .tag("protocol", flow.get("protocol", ""))
            .tag("user", flow.get("identity", {}).get("user", "unknown"))
            .tag("app_name", flow.get("app", {}).get("app_name", "unknown"))
            .tag("app_category", flow.get("app", {}).get("app_category", "unknown"))
            .tag("device_type", flow.get("identity", {}).get("device_type", "unknown"))
            .field("byte_count", float(flow.get("byte_count", 0)))
            .field("packet_count", float(flow.get("packet_count", 0)))
            .field("risk_score", float(flow.get("app", {}).get("app_risk_score", 0)))
            .time(datetime.now(timezone.utc), WritePrecision.NANOSECONDS)
        )
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)
    except Exception as e:
        log.error("InfluxDB flow write error: %s", e)


def main():
    r = redis.from_url(REDIS_URL, decode_responses=True)
    setup_redis_group(r)

    influx = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    write_api = influx.write_api(write_options=SYNCHRONOUS)

    engine = RuleEngine(RULES_PATH)
    log.info("Rule engine running — consuming from %s", ENRICHED_STREAM)

    alert_count = 0
    flow_count = 0

    while True:
        try:
            messages = r.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME,
                {ENRICHED_STREAM: ">"},
                count=50, block=1000,
            )
            if not messages:
                continue

            for stream, entries in messages:
                for msg_id, data in entries:
                    try:
                        flow = json.loads(data.get("data", "{}"))
                        flow_count += 1

                        # Determine network direction heuristic
                        dst_port = int(flow.get("dst_port") or 0)
                        flow["network_direction"] = "outbound" if dst_port > 1024 or dst_port in (80, 443, 53) else "inbound"

                        # Write flow metrics
                        write_flow_to_influx(write_api, flow)

                        # Evaluate rules
                        alerts = engine.evaluate(flow)
                        for alert in alerts:
                            alert_count += 1
                            log.warning(
                                "ALERT [%s] %s | user=%s app=%s",
                                alert["severity"],
                                alert["rule_name"],
                                alert["event"].get("user"),
                                alert["event"].get("app_name"),
                            )
                            # Publish to Redis pub/sub
                            r.publish(ALERTS_CHANNEL, json.dumps(alert))
                            # Also append to alerts stream for persistence
                            r.xadd("alerts:stream", {"data": json.dumps(alert)}, maxlen=10000)
                            # Write to InfluxDB
                            write_alert_to_influx(write_api, alert)

                        r.xack(ENRICHED_STREAM, CONSUMER_GROUP, msg_id)

                        if flow_count % 100 == 0:
                            log.info("Processed %d flows, generated %d alerts", flow_count, alert_count)

                    except Exception as e:
                        log.error("Flow processing error: %s", e)
                        r.xack(ENRICHED_STREAM, CONSUMER_GROUP, msg_id)

        except redis.exceptions.ConnectionError:
            log.warning("Redis disconnected, retrying in 3s...")
            time.sleep(3)
        except KeyboardInterrupt:
            log.info("Shutting down engine")
            break


if __name__ == "__main__":
    main()

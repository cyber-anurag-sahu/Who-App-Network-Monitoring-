"""
WhoApp — Pipeline Orchestrator
Reads raw packets from Redis stream, runs flow extraction,
identity enrichment, and app classification, then writes
enriched flows to the flows:enriched stream for the rule engine.
"""
import os
import sys
import json
import time
import logging

import redis

# Add sibling service paths so we can import modules
sys.path.insert(0, "/app/../capture")
sys.path.insert(0, "/app/../identity")
sys.path.insert(0, "/app/../fingerprint")

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [PIPELINE] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
RAW_STREAM     = "packets:raw"
ENRICHED_STREAM = "flows:enriched"
CONSUMER_GROUP  = "pipeline-group"
CONSUMER_NAME   = "pipeline-1"

r = redis.from_url(REDIS_URL, decode_responses=True)


def setup():
    try:
        r.xgroup_create(RAW_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise

    # Lazy imports (modules may not be available in all containers)
    global FlowExtractor, IdentityStore, AppClassifier
    try:
        from flow_extractor import FlowExtractor
    except ImportError:
        FlowExtractor = None
        log.warning("FlowExtractor not available — using passthrough")
    try:
        from identity_store import IdentityStore
    except ImportError:
        IdentityStore = None
        log.warning("IdentityStore not available")
    try:
        from app_classifier import AppClassifier
    except ImportError:
        AppClassifier = None
        log.warning("AppClassifier not available")


def main():
    setup()

    flow_extractor = FlowExtractor() if FlowExtractor else None
    identity_store = IdentityStore(REDIS_URL) if IdentityStore else None
    app_classifier = AppClassifier() if AppClassifier else None

    log.info("Pipeline running. Raw: %s → Enriched: %s", RAW_STREAM, ENRICHED_STREAM)
    processed = 0

    while True:
        try:
            messages = r.xreadgroup(
                CONSUMER_GROUP, CONSUMER_NAME,
                {RAW_STREAM: ">"},
                count=100, block=500,
            )
            if not messages:
                continue

            for stream, entries in messages:
                for msg_id, data in entries:
                    try:
                        pkt = json.loads(data.get("data", "{}"))

                        # Step 1: Flow extraction
                        enriched = None
                        if flow_extractor:
                            enriched = flow_extractor.ingest(pkt)
                        else:
                            enriched = pkt  # passthrough

                        if not enriched:
                            r.xack(RAW_STREAM, CONSUMER_GROUP, msg_id)
                            continue

                        # Step 2: Identity enrichment
                        if identity_store:
                            enriched = identity_store.enrich_flow(enriched)
                        else:
                            enriched.setdefault("identity", {
                                "ip": enriched.get("src_ip", ""),
                                "mac": enriched.get("src_mac", ""),
                                "hostname": enriched.get("src_ip", "unknown"),
                                "user": enriched.get("src_ip", "unknown"),
                                "device_type": "unknown",
                                "manufacturer": "Unknown",
                            })

                        # Step 3: App classification
                        if app_classifier:
                            app_info = app_classifier.classify(enriched)
                            enriched["app"] = app_info
                        else:
                            enriched.setdefault("app", {
                                "app_name": "unknown",
                                "app_category": "unknown",
                                "app_risk_score": 5,
                            })

                        # Publish enriched flow
                        r.xadd(
                            ENRICHED_STREAM,
                            {"data": json.dumps(enriched)},
                            maxlen=100_000,
                            approximate=True,
                        )
                        # Also keep a snapshot for the dashboard devices endpoint
                        ip = enriched.get("src_ip", "")
                        if ip:
                            r.setex(
                                f"device:last_flow:{ip}",
                                300,
                                json.dumps(enriched),
                            )

                        processed += 1
                        if processed % 500 == 0:
                            log.info("Pipeline: %d flows enriched", processed)

                    except Exception as e:
                        log.error("Pipeline error: %s", e)
                    finally:
                        r.xack(RAW_STREAM, CONSUMER_GROUP, msg_id)

        except redis.exceptions.ConnectionError:
            log.warning("Redis disconnected, retrying...")
            time.sleep(3)
        except KeyboardInterrupt:
            log.info("Pipeline shutting down")
            break


if __name__ == "__main__":
    main()

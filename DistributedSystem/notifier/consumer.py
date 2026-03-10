import json
import os
import time
from email.message import EmailMessage
import smtplib
from confluent_kafka import Consumer
from prometheus_client import Counter, Histogram, start_http_server

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")

KAFKA_TOPICS = os.getenv("KAFKA_TOPICS", "users,games,offers")
TOPICS = [t.strip() for t in KAFKA_TOPICS.split(",") if t.strip()]

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.ethereal.email")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", "retro-exchange@example.test")

METRICS_PORT = int(os.getenv("METRICS_PORT", "8001"))

notifier_kafka_messages_total = Counter(
    "notifier_kafka_messages_total",
    "Total Kafka messages consumed by the notifier",
    ["topic", "event_type"],
)

notifier_emails_sent_total = Counter(
    "notifier_emails_sent_total",
    "Total emails successfully sent by the notifier",
    ["event_type"],
)

notifier_email_failures_total = Counter(
    "notifier_email_failures_total",
    "Total email send failures in the notifier",
    ["event_type"],
)

notifier_email_send_seconds = Histogram(
    "notifier_email_send_seconds",
    "Time spent sending email in seconds",
    ["event_type"],
)


def log_json(stage: str, **fields):
    # One JSON object per line -> Loki json parsing is happy
    print(json.dumps({"service": "notifier", "stage": stage, **fields}), flush=True)


def send_email(to_email: str, subject: str, body: str, event_type: str):
    start = time.time()
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)

        notifier_emails_sent_total.labels(event_type=event_type).inc()
    except Exception:
        notifier_email_failures_total.labels(event_type=event_type).inc()
        raise
    finally:
        notifier_email_send_seconds.labels(event_type=event_type).observe(time.time() - start)


def subject_for(event_type: str) -> str:
    return {
        "password_changed": "Your password was changed",
        "offer_created": "New trade offer created",
        "offer_accepted": "Trade offer accepted",
        "offer_rejected": "Trade offer rejected",
    }.get(event_type, f"Notification: {event_type}")


def body_for(evt: dict) -> str:
    et = evt.get("event_type")
    request_id = evt.get("request_id")
    data = evt.get("data", {})
    links = evt.get("links", {})

    lines = [
        f"Request ID: {request_id}",
        f"Event: {et}",
        f"When: {evt.get('occurred_at')}",
        "",
    ]

    if et == "password_changed":
        lines += [
            "Your password was changed.",
            "If this wasn't you, contact support immediately.",
            "",
        ]

    if et in ("offer_created", "offer_accepted", "offer_rejected"):
        lines += [
            f"Offer ID: {data.get('offer_id')}",
            f"Status: {data.get('status')}",
            f"Requested game: {data.get('requested_game_name')} ({data.get('requested_game_id')})",
            f"Offered game:   {data.get('offered_game_name')} ({data.get('offered_game_id')})",
        ]
        reason = data.get("reason")
        if reason:
            lines.append(f"Reason: {reason}")
        lines.append("")

    if links.get("offer"):
        lines.append(f"Offer link: {links['offer']}")
    if links.get("requested_game"):
        lines.append(f"Requested game link: {links['requested_game']}")
    if links.get("offered_game"):
        lines.append(f"Offered game link: {links['offered_game']}")

    return "\n".join(lines)


def main():
    start_http_server(METRICS_PORT, addr="0.0.0.0")
    log_json("startup", metrics_port=METRICS_PORT, topics=TOPICS, bootstrap=KAFKA_BOOTSTRAP)

    consumer = Consumer(
        {
            "bootstrap.servers": KAFKA_BOOTSTRAP,
            "group.id": "retro-notifier",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": True,
        }
    )
    consumer.subscribe(TOPICS)

    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                continue

            if msg.error():
                log_json("kafka_error", error=str(msg.error()))
                continue

            topic = msg.topic() or "unknown"

            try:
                evt = json.loads(msg.value().decode("utf-8"))
            except Exception as e:
                log_json("bad_json", topic=topic, error=str(e))
                continue

            request_id = evt.get("request_id")
            event_type = evt.get("event_type", "notification")

            notifier_kafka_messages_total.labels(topic=topic, event_type=event_type).inc()

            log_json("recv", topic=topic, event_type=event_type, request_id=request_id)

            subj = subject_for(event_type)
            body = body_for(evt)

            for r in evt.get("recipients", []):
                email = r.get("email") if isinstance(r, dict) else None
                if not email:
                    continue

                try:
                    send_email(email, subj, body, event_type)
                    log_json("sent", event_type=event_type, to=email, request_id=request_id)
                except Exception as e:
                    log_json("send_failed", event_type=event_type, to=email, request_id=request_id, error=str(e))

    finally:
        consumer.close()


if __name__ == "__main__":
    time.sleep(2)
    main()
#This document was generated by ChatGPT
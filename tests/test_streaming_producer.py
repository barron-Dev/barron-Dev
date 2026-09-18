import json
import os
from uuid import uuid4
import pytest
from cyclothone.streaming.producer import EventEnvelope, EventProducer

def test_requires_bootstrap(monkeypatch):
    monkeypatch.delenv("CYCLOTHONE_KAFKA_BOOTSTRAP", raising=False)
    with pytest.raises(RuntimeError): EventProducer()

def test_requires_region(monkeypatch):
    monkeypatch.setenv("CYCLOTHONE_KAFKA_BOOTSTRAP", "redpanda:9092")
    monkeypatch.delenv("CYCLOTHONE_REGION", raising=False)
    p=EventProducer()
    with pytest.raises(RuntimeError):
        import asyncio; asyncio.run(p.publish(uuid4(),"events.endpoint","test",{}))

def test_serialization_is_deterministic_shape():
    e=EventEnvelope("e","t","r","events.endpoint","test","2026-01-01T00:00:00+00:00",{"x":1})
    raw=EventProducer._serialize(e)
    obj=json.loads(raw)
    assert obj["event_id"]=="e" and obj["tenant_id"]=="t" and obj["payload"]=={"x":1}

def test_rejects_oversized_payload(monkeypatch):
    monkeypatch.setenv("CYCLOTHONE_KAFKA_BOOTSTRAP", "redpanda:9092")
    monkeypatch.setenv("CYCLOTHONE_REGION", "eu-1")
    p=EventProducer()
    with pytest.raises(ValueError):
        import asyncio; asyncio.run(p.publish(uuid4(),"events.endpoint","test",{"x":"a"*(2_000_000)}))

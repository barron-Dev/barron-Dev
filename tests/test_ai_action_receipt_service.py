from __future__ import annotations

import pytest

from cyclothone.ai.action_receipt_service import ActionReceiptError, ActionReceiptService


def test_receipt_service_fails_closed_when_external_key_is_not_provisioned(monkeypatch):
    monkeypatch.delenv("CYCLOTHONE_AI_ACTION_SIGNING_KID", raising=False)
    monkeypatch.delenv("CYCLOTHONE_AI_ACTION_SIGNING_PRIVATE_KEY_PEM", raising=False)
    service = ActionReceiptService()
    with pytest.raises(ActionReceiptError, match="not provisioned"):
        service._load_private_key()


def test_receipt_service_rejects_malformed_external_private_key(monkeypatch):
    monkeypatch.setenv("CYCLOTHONE_AI_ACTION_SIGNING_KID", "ai-action-key-production")
    monkeypatch.setenv("CYCLOTHONE_AI_ACTION_SIGNING_PRIVATE_KEY_PEM", "not-a-private-key")
    service = ActionReceiptService()
    with pytest.raises(ActionReceiptError, match="valid unencrypted PEM"):
        service._load_private_key()

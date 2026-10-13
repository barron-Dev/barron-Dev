from cyclothone.darkweb.request_worker import _case_resolution


def test_case_resolution_reuses_the_single_case_already_linked_to_an_alert():
    plan = _case_resolution(None, [{"id": "a1", "case_id": "case-existing"}])

    assert plan == {
        "case_id": "case-existing",
        "case_ids": ["case-existing"],
        "create_case": False,
        "attach_unlinked_alerts": True,
    }


def test_case_resolution_reuses_request_case_on_retry_without_creating_another():
    plan = _case_resolution("case-request", [{"id": "a1", "case_id": "case-request"}])

    assert plan["case_id"] == "case-request"
    assert plan["create_case"] is False
    assert plan["attach_unlinked_alerts"] is True


def test_case_resolution_does_not_reassign_unlinked_alerts_across_existing_cases():
    plan = _case_resolution(
        None,
        [
            {"id": "a1", "case_id": "case-a"},
            {"id": "a2", "case_id": "case-b"},
            {"id": "a3", "case_id": None},
        ],
    )

    assert plan["case_id"] is None
    assert plan["case_ids"] == ["case-a", "case-b"]
    assert plan["create_case"] is False
    assert plan["attach_unlinked_alerts"] is False


def test_case_resolution_creates_case_only_when_no_alert_has_a_case():
    plan = _case_resolution(None, [{"id": "a1", "case_id": None}])

    assert plan["case_id"] is None
    assert plan["case_ids"] == []
    assert plan["create_case"] is True
    assert plan["attach_unlinked_alerts"] is True


def test_case_resolution_does_not_attach_unlinked_alerts_to_conflicting_request_case():
    plan = _case_resolution(
        "case-request",
        [{"id": "a1", "case_id": "case-other"}, {"id": "a2", "case_id": None}],
    )

    assert plan["case_id"] == "case-request"
    assert plan["case_ids"] == ["case-other", "case-request"]
    assert plan["create_case"] is False
    assert plan["attach_unlinked_alerts"] is False

from cyclothone.darkweb.source_inventory import SOURCE_CATALOG, inventory_for_run


def test_inventory_covers_multiple_categories_without_claiming_planned_sources_ran():
    result = inventory_for_run([
        {"source": "telegram_public", "state": "checked", "coverage": "partial"},
        {"source": "github_code", "state": "unavailable", "reason": "missing_key"},
    ])

    assert result["source_count"] == len(SOURCE_CATALOG)
    assert result["category_count"] >= 6
    categories = {item["category"]: item for item in result["categories"]}
    messaging = categories["Messaging & social"]
    telegram = next(item for item in messaging["sources"] if item["source"] == "telegram_public")
    reddit = next(item for item in messaging["sources"] if item["source"] == "reddit_public")
    assert telegram["state"] == "checked"
    assert telegram["coverage"] == "partial"
    assert reddit["state"] == "not_implemented"
    assert reddit["reason"] == "collector_not_wired"


def test_inventory_marks_historical_and_policy_excluded_sources_distinctly():
    result = inventory_for_run()
    sources = {
        source["source"]: source
        for category in result["categories"]
        for source in category["sources"]
    }

    assert sources["ransomwatch"]["state"] == "historical_only"
    assert sources["credential_dump_sources"]["state"] == "excluded"
    assert sources["tor_public_sites"]["state"] == "not_implemented"
    assert all(source["state"] != "checked" for source in sources.values())


def test_live_provider_outcomes_override_catalog_defaults():
    result = inventory_for_run([
        {"source": "pastebin_public", "state": "failed", "reason": "source_request_failed"},
        {"source": "telegram_public", "state": "checked"},
    ])
    sources = {
        source["source"]: source
        for category in result["categories"]
        for source in category["sources"]
    }
    assert sources["pastebin_public"]["state"] == "failed"
    assert sources["telegram_public"]["state"] == "checked"

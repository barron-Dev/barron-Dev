import pytest

from cyclothone.darkweb.request_worker import (
    DarkWebRequestWorker,
    InvalidTargetError,
    normalize_target,
)


def test_invalid_customer_target_uses_specific_validation_error():
    with pytest.raises(InvalidTargetError):
        normalize_target("", "domain")


@pytest.mark.asyncio
async def test_query_builder_value_error_is_not_misclassified_as_invalid_target():
    worker = DarkWebRequestWorker()
    completions = []

    async def broken_process(_request):
        raise ValueError("query dictionary should contain at least one key-value pair")

    async def complete(*args, **kwargs):
        completions.append((args, kwargs))

    worker._process = broken_process
    worker._complete = complete
    await worker._guarded({"id": "request-test"})

    assert completions == []

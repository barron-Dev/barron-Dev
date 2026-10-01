import pytest
from src.cyclothone.giril.sources import GleifLeiAdapter


def test_gleif_rejects_invalid_lei():
    with pytest.raises(ValueError):
        GleifLeiAdapter().lookup_lei("not-an-lei")


def test_gleif_rejects_invalid_page_size():
    with pytest.raises(ValueError):
        GleifLeiAdapter().search_name("Example Entity", 101)

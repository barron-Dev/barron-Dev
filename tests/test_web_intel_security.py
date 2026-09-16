from sentinel.web.crawler import WebCrawler


def test_surface_target_rejects_private_ip():
    try:
        WebCrawler._validate_target("http://127.0.0.1/", "surface")
    except ValueError:
        return
    raise AssertionError("private targets must be rejected")


def test_onion_requires_dark_layer():
    try:
        WebCrawler._validate_target("http://example.onion/", "surface")
    except ValueError:
        return
    raise AssertionError("onion targets must be classified as dark")


def test_non_onion_dark_target_rejected():
    try:
        WebCrawler._validate_target("https://example.com/", "dark")
    except ValueError:
        return
    raise AssertionError("dark targets must use onion hostnames")

from sentinel.brand.ct_logs import CTLogMonitor
def test_extract():
 s=CTLogMonitor._extract_sans({'common_name':'acme-bank.com','name_value':'acme-bank.com\nsecure.acme-bank.com'});assert 'secure.acme-bank.com' in s
def test_classify():
 assert CTLogMonitor._classify('acme-bank.com','acme.com')=='combosquat';assert CTLogMonitor._classify('acme.net','acme.com')=='tld_swap';assert CTLogMonitor._classify('xn--acme-1sa.com','acme.com')=='homoglyph'

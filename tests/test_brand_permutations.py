from cyclothone.brand.permutations import generate_permutations
def test_omission():
    p=dict(generate_permutations('acme.com'));assert 'cme.com' in p and p['cme.com']=='omission'
def test_homoglyph():assert any(t=='homoglyph' and '4' in p for p,t in generate_permutations('acme.com'))
def test_tlds():
    p=dict(generate_permutations('acme.com'));assert p['acme.net']=='tld_swap' and p['acme.ae']=='tld_swap'

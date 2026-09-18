from cyclothone.honey.tokens import generate_token,render,token_secret_hash

def test_token_is_unique_and_secret_not_hash():
    a,b=generate_token(),generate_token(); assert a.token_id!=b.token_id; assert len(a.token_secret)==64; assert token_secret_hash(a.token_secret)!=a.token_secret

def test_render_contains_no_unresolved_known_placeholders():
    t=generate_token(); out=render("[x] {{aws_key}} {{token_id}} {{year}} {{user}}",t,user="root"); assert t.aws_key in out; assert t.token_id in out; assert "{{" not in out

def test_render_never_uses_real_network_or_credentials():
    t=generate_token(); out=render("{{aws_key}} {{db_host}} {{endpoint}}",t); assert ".internal" in out; assert "amazonaws.com" not in out

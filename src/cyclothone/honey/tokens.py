from __future__ import annotations
import base64, hashlib, secrets, string
from dataclasses import dataclass
B62=string.digits+string.ascii_letters

def _b62(n:int,width:int)->str:
    out=[]
    while n:
        n,r=divmod(n,62); out.append(B62[r])
    return "".join(reversed(out)).rjust(width,"0")[:width]

@dataclass(frozen=True)
class HoneyToken:
    token_id:str; token_secret:str; aws_key:str; aws_secret:str; db_pass:str; db_host:str
    b64_blob:str; mnemonic:str; wallet_address:str; jwt:str; wg_key:str; wg_pub:str
    username:str; bic:str; endpoint:str; year:str

def generate_token()->HoneyToken:
    token_id=_b62(secrets.randbits(128),22)
    token_secret=secrets.token_hex(32)
    alphabet=string.ascii_letters+string.digits
    rand=lambda n,chars=alphabet:"".join(secrets.choice(chars) for _ in range(n))
    words=["abandon","ability","able","about","above","absent","absorb","abstract","access","accident","account","achieve","acid","acoustic","acquire","across","action","actor","actual","adapt","address","adjust","admit","adult","advance","advice","aerobic","affair","afford","afraid","again","agent","agree","ahead","aim","air","airport","aisle","alarm","album","alert","alien","all"]
    mnemonic=" ".join(secrets.choice(words) for _ in range(12))
    return HoneyToken(token_id,token_secret,"AKIA"+rand(16,string.ascii_uppercase+string.digits),rand(40),rand(24),f"db-{token_id[:8].lower()}.internal","\n".join(base64.b64encode(secrets.token_bytes(384)).decode()[i:i+70] for i in range(0,516,70)),mnemonic,"0x"+secrets.token_hex(20),base64.urlsafe_b64encode(secrets.token_bytes(120)).rstrip(b"=").decode(),base64.b64encode(secrets.token_bytes(32)).decode(),base64.b64encode(secrets.token_bytes(32)).decode(),f"svc_{token_id[:6].lower()}","HONEY"+token_id[:6].upper(),f"swift-{token_id[:6].lower()}.internal:7600",__import__("datetime").datetime.now(__import__("datetime").timezone.utc).year.__str__())

def render(template:str,tok:HoneyToken,beacon_url:str|None=None,hostname:str="host",user:str="user")->str:
    values={"token_id":tok.token_id,"token_secret":tok.token_secret,"aws_key":tok.aws_key,"aws_secret":tok.aws_secret,"db_pass":tok.db_pass,"db_host":tok.db_host,"b64_blob":tok.b64_blob,"mnemonic":tok.mnemonic,"wallet_address":tok.wallet_address,"jwt":tok.jwt,"wg_key":tok.wg_key,"wg_pub":tok.wg_pub,"username":tok.username,"bic":tok.bic,"endpoint":tok.endpoint,"year":tok.year,"beacon_url":beacon_url or "","domain":"internal","hostname":hostname,"user":user,"region":"us-east-1","mbox_blob":f"From: ceo@{hostname}.internal\\nX-Cyclothone-Beacon: {beacon_url or tok.token_id}","xlsx_blob":f"Cyclothone-HONEY-{tok.token_id}","sqlite_blob":f"CYCL-HONEY-{tok.token_id}","token":tok.token_secret}
    out=template
    for k,v in values.items(): out=out.replace("{{"+k+"}}",v)
    return out

def token_secret_hash(secret:str)->str:return hashlib.sha256(secret.encode()).hexdigest()

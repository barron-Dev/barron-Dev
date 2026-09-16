from __future__ import annotations

KEYBOARD_NEIGHBORS = {"a":"qsz","b":"vghn","c":"xdfv","d":"serfcx","e":"wrsdf","f":"drtgvc","g":"ftyhbv","h":"gyujnb","i":"ujko","j":"huikmn","k":"jiolm","l":"kop","m":"njk","n":"bhjm","o":"iklp","p":"ol","q":"wa","r":"edft","s":"awedxz","t":"rfgy","u":"yhji","v":"cfgb","w":"qase","x":"zsdc","y":"tghu","z":"asx"}
HOMOGLYPHS = {"a":["4","@"],"b":["6"],"e":["3"],"g":["9"],"i":["1","l"],"l":["1","i"],"o":["0"],"s":["5","$"],"t":["7"],"z":["2"],"m":["rn"],"n":["m"]}
COMMON_TLDS = ["com","net","org","io","co","app","dev","ae","sa","eg","ke","ng","za","gh","tz","ug","ma","dz","tn","in","sg","my","id","ph","th","vn","jp","kr","cn","co.uk","com.au","co.za","com.ng","co.ke","com.sa","com.ae"]

def generate_permutations(domain: str, max_n: int = 5000) -> list[tuple[str,str]]:
    host = domain.lower().strip().rstrip('.')
    base, _, tld = host.rpartition('.')
    if not base: base, tld = host, 'com'
    out: set[tuple[str,str]] = set()
    for i in range(len(base)):
        out.add((f"{base[:i]}{base[i+1:]}.{tld}","omission"))
        out.add((f"{base[:i]}{base[i]}{base[i:]}.{tld}","duplication"))
    for i in range(len(base)-1):
        out.add((f"{base[:i]}{base[i+1]}{base[i]}{base[i+2:]}.{tld}","transposition"))
    for i,c in enumerate(base):
        for n in KEYBOARD_NEIGHBORS.get(c,''): out.add((f"{base[:i]}{n}{base[i+1:]}.{tld}","keyboard"))
        for h in HOMOGLYPHS.get(c,[]): out.add((f"{base[:i]}{h}{base[i+1:]}.{tld}","homoglyph"))
    for i in range(1,len(base)): out.add((f"{base[:i]}-{base[i:]}.{tld}","hyphenation"))
    for p in ("secure","login","account","my","portal","support","help","verify","mail"):
        out.update({(f"{p}-{base}.{tld}","combosquat"),(f"{base}-{p}.{tld}","combosquat"),(f"{p}{base}.{tld}","combosquat")})
    for t in COMMON_TLDS:
        if t != tld: out.add((f"{base}.{t}","tld_swap"))
    for a in ("app","web","online","site","co","group","global","services"):
        out.update({(f"{base}{a}.{tld}","combosquat"),(f"{a}{base}.{tld}","combosquat")})
    result=[]; seen=set()
    for p,t in out:
        if p in seen or not 4 <= len(p) <= 253: continue
        seen.add(p); result.append((p,t))
        if len(result)>=max_n: break
    return result

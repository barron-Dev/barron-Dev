from __future__ import annotations
import math
from collections import Counter

def levenshtein(a: str, b: str) -> int:
    prev=list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        cur=[i]
        for j,cb in enumerate(b,1): cur.append(min(cur[-1]+1,prev[j]+1,prev[j-1]+(ca!=cb)))
        prev=cur
    return prev[-1]

def jaro(a: str,b: str)->float:
    if a==b:return 1.0
    if not a or not b:return 0.0
    d=max(len(a),len(b))//2-1; am=[0]*len(a); bm=[0]*len(b); m=0
    for i,c in enumerate(a):
        for j in range(max(0,i-d),min(i+d+1,len(b))):
            if not bm[j] and b[j]==c: am[i]=1;bm[j]=1;m+=1;break
    if not m:return 0.0
    x=[a[i] for i,v in enumerate(am) if v]; y=[b[i] for i,v in enumerate(bm) if v]
    t=sum(x[i]!=y[i] for i in range(m))//2
    return (m/len(a)+m/len(b)+(m-t)/m)/3

def jaro_winkler(a:str,b:str,p:float=.1)->float:
    j=jaro(a,b); pre=0
    for x,y in zip(a,b):
        if x!=y or pre==4: break
        pre+=1
    return j+pre*p*(1-j)

def ngram_cosine(a:str,b:str,n:int=2)->float:
    def c(s): return Counter(s.lower()[i:i+n] for i in range(max(0,len(s)-n+1)))
    x,y=c(a),c(b)
    if not x or not y:return 0.0
    dot=sum(x[k]*y[k] for k in x.keys()&y.keys()); nx=math.sqrt(sum(v*v for v in x.values())); ny=math.sqrt(sum(v*v for v in y.values()))
    return dot/(nx*ny) if nx and ny else 0.0

def combined_similarity(a:str,b:str)->float:
    a=a.lower().strip();b=b.lower().strip()
    if a==b:return 1.0
    ml=max(len(a),len(b),1)
    return round(.4*(1-levenshtein(a,b)/ml)+.35*jaro_winkler(a,b)+.25*ngram_cosine(a,b),4)

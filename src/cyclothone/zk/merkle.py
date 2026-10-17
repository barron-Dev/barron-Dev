from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass
@dataclass(frozen=True)
class MerkleProof:
    leaf:str
    index:int
    path:list[tuple[str,str]]
class MerkleTree:
    DOMAIN=b"cyclothone.zk.merkle.v1\0"
    def __init__(self,leaves:list[str]):
        if not leaves or any(len(x)!=64 or any(c not in "0123456789abcdef" for c in x.lower()) for x in leaves):
            raise ValueError("invalid leaves")
        self.leaves=[x.lower() for x in leaves]; self.levels=[self.leaves]; self._build()
    @staticmethod
    def _hash_pair(a:str,b:str)->str:
        return hashlib.sha256(MerkleTree.DOMAIN+bytes.fromhex(a)+bytes.fromhex(b)).hexdigest()
    def _build(self):
        cur=self.leaves
        while len(cur)>1:
            cur=[self._hash_pair(cur[i],cur[i+1] if i+1<len(cur) else cur[i]) for i in range(0,len(cur),2)]
            self.levels.append(cur)
    @property
    def root(self)->str: return self.levels[-1][0]
    def proof(self,index:int)->MerkleProof:
        if not 0<=index<len(self.leaves): raise IndexError("leaf index out of range")
        path=[]; i=index
        for level in self.levels[:-1]:
            sibling=level[i+1] if i%2==0 and i+1<len(level) else level[i-1] if i%2 else level[i]
            path.append((sibling,"R" if i%2==0 else "L")); i//=2
        return MerkleProof(self.leaves[index],index,path)
    @staticmethod
    def verify(leaf:str,index:int,path:list[tuple[str,str]],root:str)->bool:
        try:
            if index<0 or len(leaf)!=64 or len(root)!=64: return False
            cur=leaf.lower(); i=index
            for sibling,direction in path:
                if direction not in ("L","R") or len(sibling)!=64: return False
                cur=MerkleTree._hash_pair(cur,sibling.lower()) if direction=="R" else MerkleTree._hash_pair(sibling.lower(),cur); i//=2
            return secrets.compare_digest(cur,root.lower())
        except (ValueError,TypeError): return False

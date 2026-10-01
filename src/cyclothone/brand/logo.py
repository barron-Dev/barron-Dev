from __future__ import annotations
import io
class LogoMatcher:
    def _hash(self,b:bytes,size:int=16,diff:bool=False)->str:
        try:
            from PIL import Image
            img=Image.open(io.BytesIO(b)).convert('L').resize((size+1,size) if diff else (size,size))
            px=list(img.getdata())
            if diff: bits=''.join('1' if px[r*(size+1)+c]>px[r*(size+1)+c+1] else '0' for r in range(size) for c in range(size))
            else:
                avg=sum(px)/len(px); bits=''.join('1' if p>avg else '0' for p in px)
            return f'{int(bits,2):0{size*size//4}x}'
        except Exception:return ''
    def ahash(self,image_bytes:bytes,size:int=16)->str:return self._hash(image_bytes,size)
    def dhash(self,image_bytes:bytes,size:int=16)->str:return self._hash(image_bytes,size,True)
    def hamming(self,a:str,b:str)->int:
        if not a or not b or len(a)!=len(b):return 999
        try:return (int(a,16)^int(b,16)).bit_count()
        except ValueError:return 999
    def similarity(self,a:str,b:str)->float:
        d=self.hamming(a,b)
        return 0.0 if d>=999 else max(0.0,1-d/(len(a)*4))

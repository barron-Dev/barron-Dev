from __future__ import annotations
import asyncio,logging,time
from sentinel.brand.ct_logs import CTLogMonitor
from sentinel.brand.typosquat import TyposquatScanner
from sentinel.brand.social import SocialMonitor
from sentinel.brand.apps import AppStoreMonitor
from sentinel.storage.supabase_client import supabase
logger=logging.getLogger(__name__)
class BrandScheduler:
    CT_INTERVAL=3600; TYPOSQUAT_INTERVAL=86400; SOCIAL_INTERVAL=86400
    def __init__(self):self._task=None;self._stop=asyncio.Event();self._last_typo=0.;self._last_social=0.
    def start(self):
        if self._task is None or self._task.done():self._stop.clear();self._task=asyncio.create_task(self._loop(),name='sentinel-brand')
    async def stop(self):
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:await self._task
            except asyncio.CancelledError:pass
            self._task=None
    async def _brands(self):
        async def q():return await (await supabase._ensure()).table('brands').select('*').eq('enabled',True).execute()
        try:return list((await supabase._retry(q,attempts=2)).data or [])
        except Exception:return []
    async def _scan(self,scanner):
        for b in await self._brands():
            try:await scanner.scan_brand(b)
            except Exception:logger.exception('brand scan failed id=%s',b.get('id'))
    async def _loop(self):
        await asyncio.sleep(120)
        while not self._stop.is_set():
            try:await CTLogMonitor().match_brands()
            except asyncio.CancelledError:raise
            except Exception:logger.exception('brand CT tick failed')
            now=time.time()
            if now-self._last_typo>=self.TYPOSQUAT_INTERVAL:
                await self._scan(TyposquatScanner());self._last_typo=now
            if now-self._last_social>=self.SOCIAL_INTERVAL:
                await self._scan(SocialMonitor());await self._scan(AppStoreMonitor());self._last_social=now
            try:await asyncio.wait_for(self._stop.wait(),timeout=self.CT_INTERVAL)
            except asyncio.TimeoutError:pass

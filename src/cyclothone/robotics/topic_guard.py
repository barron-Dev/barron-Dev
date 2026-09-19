from __future__ import annotations
from collections import defaultdict,deque
from dataclasses import dataclass,field
@dataclass
class TopicObservation: topic:str; publisher_id:str; msg_hash:str; ts:float
@dataclass
class TopicGuard:
    window_seconds:int=60; max_publishers_per_topic:int=3; max_hz_variance:float=.5
    _window:dict[str,deque]=field(default_factory=lambda:defaultdict(deque))
    _baseline_hz:dict[str,float]=field(default_factory=dict)
    _known_publishers:dict[str,set[str]]=field(default_factory=lambda:defaultdict(set))
    def observe(self,obs:TopicObservation)->list[dict]:
        dq=self._window[obs.topic]; dq.append(obs); cutoff=obs.ts-self.window_seconds
        while dq and dq[0].ts<cutoff: dq.popleft()
        findings=[]; known=self._known_publishers[obs.topic]
        if not known: known.add(obs.publisher_id)
        elif obs.publisher_id not in known:
            if obs.topic in {"/cmd_vel","/emergency_stop","/kill_switch"}:
                findings.append({"kind":"unauth_publisher","severity":"critical","detail":f"New publisher '{obs.publisher_id}' on {obs.topic}.","evidence":{"topic":obs.topic,"publisher":obs.publisher_id}})
            known.add(obs.publisher_id)
        pubs={o.publisher_id for o in dq}
        if len(pubs)>self.max_publishers_per_topic: findings.append({"kind":"topic_hijack","severity":"high","detail":f"{len(pubs)} publishers on {obs.topic}.","evidence":{"topic":obs.topic,"publishers":sorted(pubs)}})
        if len(dq)>=10:
            hz=len(dq)/self.window_seconds; base=self._baseline_hz.get(obs.topic)
            if base is None: self._baseline_hz[obs.topic]=hz
            else:
                delta=abs(hz-base)/max(base,.01)
                if delta>self.max_hz_variance:
                    findings.append({"kind":"frequency_anomaly","severity":"medium","detail":f"{obs.topic} rate changed {delta*100:.0f}%.","evidence":{"topic":obs.topic,"base_hz":base,"current_hz":hz}})
                    self._baseline_hz[obs.topic]=.9*base+.1*hz
        return findings

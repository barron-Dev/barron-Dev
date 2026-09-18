package online.cyclothone.streams.model;
import java.time.Instant;
import java.util.Map;
public record EventEnvelope(String eventId,String tenantId,String region,String kind,String entityKey,Instant eventTime,double score,Map<String,Object> attributes) {
  public EventEnvelope {
    if (eventId==null||eventId.isBlank()) throw new IllegalArgumentException("eventId required");
    if (tenantId==null||tenantId.isBlank()) throw new IllegalArgumentException("tenantId required");
    if (region==null||region.isBlank()) throw new IllegalArgumentException("region required");
    if (kind==null||kind.isBlank()) throw new IllegalArgumentException("kind required");
    if (entityKey==null||entityKey.isBlank()) throw new IllegalArgumentException("entityKey required");
    if (eventTime==null) throw new IllegalArgumentException("eventTime required");
    if (!Double.isFinite(score)||score<0||score>1) throw new IllegalArgumentException("score must be in [0,1]");
    attributes=attributes==null?Map.of():Map.copyOf(attributes);
  }
  public String correlationKey(){ return tenantId+"|"+entityKey; }
}

package online.cyclothone.streams.model;
import java.time.Instant;
public record DeadLetterEvent(String eventId,String tenantId,String region,String sourceTopic,String sourceKey,String reason,String errorClass,Instant observedAt,String payloadFingerprint) {
  public DeadLetterEvent {
    if (sourceTopic==null||sourceTopic.isBlank()) throw new IllegalArgumentException("sourceTopic required");
    if (reason==null||reason.isBlank()) throw new IllegalArgumentException("reason required");
    if (observedAt==null) throw new IllegalArgumentException("observedAt required");
  }
}
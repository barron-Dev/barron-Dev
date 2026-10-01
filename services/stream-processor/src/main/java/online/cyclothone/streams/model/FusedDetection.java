package online.cyclothone.streams.model;
import java.time.Instant;
import java.util.Set;
public record FusedDetection(String tenantId,String region,String correlationKey,Instant firstEventTime,Instant lastEventTime,double fusedScore,String severity,Set<String> eventIds,int eventCount) {}

package online.cyclothone.streams;
import online.cyclothone.streams.model.EventEnvelope;
import org.apache.kafka.streams.StreamsBuilder;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
class FusionTopologyTest {
 @Test void tenantKeyIsDeterministic(){var e=new EventEnvelope("e1","tenant-a","eu-1","network","host-7",Instant.parse("2026-09-19T00:00:00Z"),.8,Map.of());assertEquals("tenant-a|host-7",e.correlationKey());}
 @Test void invalidScoreRejected(){assertThrows(IllegalArgumentException.class,()->new EventEnvelope("e1","t","r","network","h",Instant.now(),1.1,Map.of()));}
 @Test void topologyBuilds(){var b=new StreamsBuilder();assertNotNull(FusionTopology.build(b,new String[]{"events.network"},"detections.fused"));}
}

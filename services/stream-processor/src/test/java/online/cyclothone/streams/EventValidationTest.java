package online.cyclothone.streams;
import online.cyclothone.streams.model.EventEnvelope;
import online.cyclothone.streams.validation.EventValidator;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
class EventValidationTest {
 @Test void unsupportedKindIsRejected(){var e=new EventEnvelope("e","t","r","bogus","x",Instant.now(),.2,Map.of());assertEquals("unsupported kind",EventValidator.validate(e));}
 @Test void validEventPasses(){var e=new EventEnvelope("e","t","r","network","x",Instant.now(),.2,Map.of());assertNull(EventValidator.validate(e));}
}
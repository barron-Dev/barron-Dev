package online.cyclothone.streams.validation;
import online.cyclothone.streams.model.EventEnvelope;
import java.util.Set;
public final class EventValidator {
  private static final Set<String> KINDS=Set.of("endpoint","network","identity","cloud","physical","banking","telecom","satellite","ai","lens","federation","detection");
  private EventValidator(){}
  public static String validate(EventEnvelope e) {
    if(e==null)return "null event";
    if(e.eventId().length()>128)return "eventId too long";
    if(e.tenantId().length()>128)return "tenantId too long";
    if(e.region().length()>64)return "region too long";
    if(e.entityKey().length()>512)return "entityKey too long";
    if(e.kind().length()>64)return "kind too long";
    if(!KINDS.contains(e.kind()))return "unsupported kind";
    return null;
  }
}
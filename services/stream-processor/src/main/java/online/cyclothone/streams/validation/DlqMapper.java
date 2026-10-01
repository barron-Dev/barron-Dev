package online.cyclothone.streams.validation;
import online.cyclothone.streams.model.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
public final class DlqMapper {
 private DlqMapper(){}
 public static DeadLetterEvent invalid(EventEnvelope e,String topic,String key,String reason){
  return new DeadLetterEvent(e==null?null:e.eventId(),e==null?null:e.tenantId(),e==null?null:e.region(),topic,key,reason,e==null?null:"EventValidation",Instant.now(),fingerprint(e));
 }
 private static String fingerprint(EventEnvelope e){
  try{return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(String.valueOf(e).getBytes(StandardCharsets.UTF_8)));}
  catch(Exception x){throw new IllegalStateException("fingerprint failure",x);}
 }
}
package online.cyclothone.streams.serde;
import online.cyclothone.streams.model.EventEnvelope;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.streams.processor.TimestampExtractor;
public final class EventTimestampExtractor implements TimestampExtractor {
  public long extract(ConsumerRecord<Object,Object> record,long partitionTime){
    if(!(record.value() instanceof EventEnvelope e)) throw new IllegalArgumentException("event-time extraction requires EventEnvelope");
    long ts=e.eventTime().toEpochMilli();
    if(ts<0) throw new IllegalArgumentException("eventTime before epoch");
    return ts;
  }
}

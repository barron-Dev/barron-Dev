package online.cyclothone.streams;
import online.cyclothone.streams.model.*;
import online.cyclothone.streams.serde.*;
import online.cyclothone.streams.validation.*;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.*;
import org.apache.kafka.streams.kstream.*;
import java.time.*;
import java.util.*;
public final class FusionTopology {
 private FusionTopology(){}
 public static Topology build(StreamsBuilder builder,String[] inputTopics,String outputTopic,String dlqTopic){
  JsonSerde<EventEnvelope> es=new JsonSerde<>(EventEnvelope.class); JsonSerde<FusedDetection> fs=new JsonSerde<>(FusedDetection.class); JsonSerde<DeadLetterEvent> ds=new JsonSerde<>(DeadLetterEvent.class);
  KStream<String,EventEnvelope> merged=null;
  for(String topic:inputTopics){
   KStream<String,EventEnvelope> s=builder.stream(topic,Consumed.with(Serdes.String(),es).withTimestampExtractor(new EventTimestampExtractor()));
   KStream<String,EventEnvelope> valid=s.filter((k,v)->v!=null&&EventValidator.validate(v)==null);
   s.filter((k,v)->v!=null&&EventValidator.validate(v)!=null)
    .map((k,v)->KeyValue.pair(k,DlqMapper.invalid(v,topic,k,EventValidator.validate(v))))
    .to(dlqTopic,Produced.with(Serdes.String(),ds));
   merged=merged==null?valid:merged.merge(valid);
  }
  if(merged==null)throw new IllegalArgumentException("inputTopics required");
  TimeWindows windows=TimeWindows.ofSizeAndGrace(Duration.ofSeconds(30),Duration.ofSeconds(10));
  KTable<Windowed<String>,FusionAccumulator> table=merged.selectKey((k,v)->v.correlationKey())
   .groupByKey(Grouped.with(Serdes.String(),es)).windowedBy(windows)
   .aggregate(FusionAccumulator::new,(key,e,a)->a.add(e),Materialized.with(Serdes.String(),new JsonSerde<>(FusionAccumulator.class)));
  table.toStream().filter((w,a)->a!=null&&!a.eventIds.isEmpty())
   .map((w,a)->KeyValue.pair(w.key(),a.toDetection(w.key(),w.window().startTime().toInstant())))
   .to(outputTopic,Produced.with(Serdes.String(),fs));
  return builder.build();
 }
 public static Topology build(StreamsBuilder b,String[] i,String o){return build(b,i,o,"stream.dlq");}
 public static final class FusionAccumulator {
  public String tenantId; public String region; public Instant firstEventTime; public Instant lastEventTime; public double maxScore; public LinkedHashSet<String> eventIds=new LinkedHashSet<>();
  public FusionAccumulator add(EventEnvelope e){
   if(eventIds.contains(e.eventId()))return this;
   if(tenantId==null)tenantId=e.tenantId(); if(region==null)region=e.region();
   if(!tenantId.equals(e.tenantId()))throw new IllegalStateException("cross-tenant aggregation");
   eventIds.add(e.eventId()); if(eventIds.size()>128)eventIds.remove(eventIds.iterator().next());
   firstEventTime=firstEventTime==null||e.eventTime().isBefore(firstEventTime)?e.eventTime():firstEventTime;
   lastEventTime=lastEventTime==null||e.eventTime().isAfter(lastEventTime)?e.eventTime():lastEventTime;
   maxScore=Math.max(maxScore,e.score()); return this;
  }
  public FusedDetection toDetection(String key,Instant ws){
   String sev=maxScore>=.85?"critical":maxScore>=.65?"high":maxScore>=.40?"medium":"low";
   return new FusedDetection(tenantId,region,key,firstEventTime==null?ws:firstEventTime,lastEventTime==null?ws:lastEventTime,maxScore,sev,Set.copyOf(eventIds),eventIds.size());
  }
 }
}
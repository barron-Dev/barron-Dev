package online.cyclothone.streams;
import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.streams.*;
import java.time.Duration;
import java.util.*;
public final class StreamProcessorApplication {
  private static final String[] DEFAULT_INPUTS={"events.endpoint","events.network","events.identity","events.cloud","events.physical","events.banking","events.telecom","events.satellite","events.ai","events.lens","events.federation","detections.raw"};
  public static void main(String[] args){
    String bootstrap=req("CYCLOTHONE_KAFKA_BOOTSTRAP"),region=req("CYCLOTHONE_REGION"),app=req("CYCLOTHONE_STREAMS_APPLICATION_ID");
    Properties p=new Properties();
    p.put(StreamsConfig.APPLICATION_ID_CONFIG,app+"-"+region);
    p.put(StreamsConfig.BOOTSTRAP_SERVERS_CONFIG,bootstrap);
    p.put(StreamsConfig.DEFAULT_KEY_SERDE_CLASS_CONFIG,Serdes.StringSerde.class.getName());
    p.put(StreamsConfig.PROCESSING_GUARANTEE_CONFIG,StreamsConfig.EXACTLY_ONCE_V2);
    p.put(StreamsConfig.REPLICATION_FACTOR_CONFIG,Integer.parseInt(System.getenv().getOrDefault("CYCLOTHONE_STREAMS_REPLICATION_FACTOR","3")));
    p.put(StreamsConfig.NUM_STANDBY_REPLICAS_CONFIG,1);
    p.put(StreamsConfig.COMMIT_INTERVAL_MS_CONFIG,100);
    p.put(StreamsConfig.STATE_DIR_CONFIG,System.getenv().getOrDefault("CYCLOTHONE_STREAMS_STATE_DIR","/var/lib/cyclothone/streams"));
    p.put(StreamsConfig.TOPOLOGY_OPTIMIZATION_CONFIG,StreamsConfig.OPTIMIZE);
    StreamsBuilder b=new StreamsBuilder();
    Topology t=FusionTopology.build(b,csv(System.getenv().getOrDefault("CYCLOTHONE_STREAM_INPUTS",String.join(",",DEFAULT_INPUTS))),"detections.fused");
    KafkaStreams streams=new KafkaStreams(t,p);
    Runtime.getRuntime().addShutdownHook(new Thread(()->streams.close(Duration.ofSeconds(30))));
    streams.start();
  }
  private static String req(String k){String v=System.getenv(k);if(v==null||v.isBlank())throw new IllegalStateException(k+" is required");return v;}
  private static String[] csv(String v){return Arrays.stream(v.split(",")).map(String::trim).filter(s->!s.isBlank()).toArray(String[]::new);}
}

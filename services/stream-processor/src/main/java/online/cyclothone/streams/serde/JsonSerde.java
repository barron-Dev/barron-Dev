package online.cyclothone.streams.serde;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.kafka.common.serialization.*;
import java.io.IOException;
public final class JsonSerde<T> implements Serde<T> {
  private final ObjectMapper mapper=new ObjectMapper().registerModule(new JavaTimeModule());
  private final Class<T> type;
  public JsonSerde(Class<T> type){this.type=type;}
  public Serializer<T> serializer(){return (topic,data)->{if(data==null)return null;try{return mapper.writeValueAsBytes(data);}catch(IOException e){throw new IllegalArgumentException("serialization failed",e);}};}
  public Deserializer<T> deserializer(){return (topic,data)->{if(data==null)return null;try{return mapper.readValue(data,type);}catch(IOException e){throw new IllegalArgumentException("deserialization failed",e);}};}
}

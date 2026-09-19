package online.cyclothone.bridge.hsm;

/** Production HSM abstraction. Implementations must keep private/master keys non-exportable. */
public interface HsmSigner {
  byte[] sign(String keyAlias, byte[] digest) throws HsmException;
  boolean verify(String keyAlias, byte[] digest, byte[] signature) throws HsmException;
  class HsmException extends Exception {
    public HsmException(String message, Throwable cause) { super(message, cause); }
  }
}

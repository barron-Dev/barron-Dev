package online.cyclothone.bridge.security;

import java.util.Set;
import java.util.regex.Pattern;
import online.cyclothone.bridge.v1.Indicator;

/** Contract-level validation before any indicator reaches the ingestion boundary. */
public final class IndicatorValidator {
  private static final Pattern HASH = Pattern.compile("^[0-9a-fA-F]{16,128}$");
  private static final Set<String> TYPES = Set.of("ipv4","ipv6","domain","url","sha256","sha1","md5","email","phone","user");
  private IndicatorValidator() {}
  public static boolean valid(Indicator i) {
    if (i == null || i.getIocType().isBlank() || i.getValueHash().isBlank()) return false;
    if (!TYPES.contains(i.getIocType().toLowerCase())) return false;
    if (!HASH.matcher(i.getValueHash()).matches()) return false;
    return i.getConfidence() >= 0f && i.getConfidence() <= 1f;
  }
}

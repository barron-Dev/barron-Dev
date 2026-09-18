package online.cyclothone.bridge.security;

import java.util.UUID;

/** Authorization boundary: authentication context, not a caller-supplied tenant field, decides access. */
public interface TenantAuthorizer {
  void assertAuthorized(UUID authenticatedTenant, UUID requestedTenant);
}

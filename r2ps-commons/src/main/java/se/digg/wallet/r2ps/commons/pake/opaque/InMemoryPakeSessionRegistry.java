package se.digg.wallet.r2ps.commons.pake.opaque;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class InMemoryPakeSessionRegistry<T extends PakeSessionRegistryRecord>
    implements PakeSessionRegistry<T> {

  protected Map<String, T> pakeSessions;

  public InMemoryPakeSessionRegistry() {
    this.pakeSessions = new HashMap<>();
  }

  @Override
  public List<T> getPakeSessions(final String clientId, final String kid) {
    return pakeSessions.values().stream()
        .filter(t -> t.getClientId().equals(clientId))
        .filter(t -> t.getKid().equals(kid))
        .toList();
  }

  @Override
  public List<T> getPakeSessions(final String clientId, final String kid, final String context) {
    return pakeSessions.values().stream()
        .filter(t -> t.getClientId().equals(clientId))
        .filter(t -> t.getKid().equals(kid))
        .filter(t -> t.getContext().equals(context))
        .toList();
  }

  @Override
  public T getPakeSession(String pakeSessionId) {
    if (pakeSessionId == null) {
      return null;
    }
    return pakeSessions.get(pakeSessionId);
  }

  @Override
  public void addPakeSession(final T pakeSessionRegistryRecord) {
    Objects.requireNonNull(
        pakeSessionRegistryRecord.getPakeSessionId(), "The pakeSessionId is null");
    Objects.requireNonNull(pakeSessionRegistryRecord.getClientId(), "The clientId is null");
    Objects.requireNonNull(pakeSessionRegistryRecord.getKid(), "The key identifier is null");
    pakeSessions.put(pakeSessionRegistryRecord.getPakeSessionId(), pakeSessionRegistryRecord);
  }

  @Override
  public void updatePakeSession(final T pakeSessionRegistryRecord) {
    addPakeSession(pakeSessionRegistryRecord);
  }

  @Override
  public void deletePakeSession(final String pakeSessionId) {
    pakeSessions.remove(pakeSessionId);
  }

  @Override
  public void purgeRecords() {
    this.pakeSessions =
        pakeSessions.entrySet().stream()
            .filter(entry -> Instant.now().isBefore(entry.getValue().getExpirationTime()))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }
}

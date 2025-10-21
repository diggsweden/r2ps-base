package se.digg.wallet.r2ps.server.service.impl;

import lombok.extern.slf4j.Slf4j;
import se.digg.wallet.r2ps.server.service.ReplayChecker;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class RpsOpsReplayChecker implements ReplayChecker {

  private final Duration replayCheckDuration;
  private final Map<String, Instant> nonceMap;

  public RpsOpsReplayChecker(final Duration replayCheckDuration) {
    this.replayCheckDuration = replayCheckDuration;
    this.nonceMap = new HashMap<>();
  }

  @Override
  public boolean isReplay(final String nonce) {
    // Remove expired nonces from noncemap
    nonceMap.entrySet()
        .removeIf(entry -> Instant.now().isAfter(entry.getValue().plus(replayCheckDuration)));

    boolean replay = nonceMap.containsKey(nonce);
    nonceMap.put(nonce, Instant.now());
    return replay;
  }
}

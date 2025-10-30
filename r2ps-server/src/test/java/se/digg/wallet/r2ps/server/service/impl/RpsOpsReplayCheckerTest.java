package se.digg.wallet.r2ps.server.service.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class RpsOpsReplayCheckerTest {
  @Test
  void testIsReplayTest() throws Exception {
    RpsOpsReplayChecker replayChecker = new RpsOpsReplayChecker(Duration.ofMillis(200));
    assertFalse(replayChecker.isReplay("nonce1"));
    assertFalse(replayChecker.isReplay("nonce2"));
    assertTrue(replayChecker.isReplay("nonce1"));
    assertTrue(replayChecker.isReplay("nonce2"));
    Thread.sleep(200);
    assertFalse(replayChecker.isReplay("nonce1"));
    assertFalse(replayChecker.isReplay("nonce2"));
    assertTrue(replayChecker.isReplay("nonce1"));
    assertTrue(replayChecker.isReplay("nonce2"));
  }
}

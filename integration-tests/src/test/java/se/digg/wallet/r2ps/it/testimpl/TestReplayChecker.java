package se.digg.wallet.r2ps.it.testimpl;

import se.digg.wallet.r2ps.server.service.ReplayChecker;

public class TestReplayChecker implements ReplayChecker {
  @Override
  public boolean isReplay(String nonce) {
    return false;
  }
}

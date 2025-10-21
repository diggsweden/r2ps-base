package se.digg.wallet.r2ps.server.service;

public interface ReplayChecker {

  boolean isReplay(String nonce);
}

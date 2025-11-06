package se.digg.wallet.r2ps.client.pake.impl;

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.wallet.r2ps.client.pake.PinHardening;
import se.digg.wallet.r2ps.test.data.TestCredentials;

@Slf4j
class ECPrivateKeyDHPinHardeningTest {

  @BeforeAll
  static void setUp() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
  }

  @Test
  void seedPin() {
    String pin = "123456";

    PinHardening pinSeeder =
        new ECPrivateKeyDHPinHardening(HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_);
    final byte[] seededPin = pinSeeder.process(pin, TestCredentials.p256keyPair.getPrivate(), 32);

    assertEquals(
        "e784ca50762b11f22d07cd61b5388a692faec4159080c8de6ac98567a69eb685",
        Hex.toHexString(seededPin));
  }
}

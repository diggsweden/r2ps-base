package se.digg.wallet.r2ps.server.pake.opaque;

import java.time.Instant;

public record FinalizeResponse(
    String pakeSessionId,
    Instant sessionExpirationTime,
    String sessionTask
) {
}

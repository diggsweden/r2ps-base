package se.digg.wallet.r2ps.server.pake.opaque;

import se.digg.crypto.opaque.dto.KE2;

public record EvaluationResponseResult(KE2 ke2, String pakeSessionId) {
}

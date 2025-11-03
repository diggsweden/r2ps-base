package se.digg.wallet.r2ps.commons.dto.servicetype;

import java.time.Duration;

public record SessionTask(String id, Duration maxDuration) {
}

package se.digg.wallet.r2ps.client.api.impl;

import se.digg.crypto.opaque.client.ClientState;

public record AuthenticationCredentialResponse(
    String pakeSessionId, byte[] responseData, ClientState clientState) {
}

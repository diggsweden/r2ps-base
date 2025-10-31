package se.digg.wallet.r2ps.client.api.impl;

public record PinCredentialResponse(byte[] responseData, byte[] blind) {}

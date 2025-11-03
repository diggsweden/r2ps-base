package se.digg.wallet.r2ps.commons.dto;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;

public record JWSSigningParams(JWSSigner signer, JWSAlgorithm algorithm) {
}

package se.digg.wallet.r2ps.commons.dto.payload;

public interface HSMParams {
  // Parameter names
  String KEY_IDENTIFIER = "kid";
  String PUBLIC_KEY = "public_key";
  String TBS_HASH = "tbs_hash";
  String CURVE = "curve";
  String CREATED_KEY = "created_key";

  // Parameter values
  String OPTION_SIGN_HASHED = "sign_hashed";
  String OPTION_DIFFIE_HELLMAN = "dh";
}

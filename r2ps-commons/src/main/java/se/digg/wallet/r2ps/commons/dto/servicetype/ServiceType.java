package se.digg.wallet.r2ps.commons.dto.servicetype;

import se.digg.wallet.r2ps.commons.dto.EncryptOption;

public record ServiceType(
    String id,
    EncryptOption encryptKey
) {
  public static final String AUTHENTICATE = "authenticate";
  public static final String PIN_REGISTRATION = "pin_registration";
  public static final String PIN_CHANGE = "pin_change";
  public static final String HSM_ECDSA = "hsm_ecdsa";
  public static final String HSM_ECDH = "hsm_ecdh";
  public static final String HSM_KEYGEN = "hsm_ec_keygen";
  public static final String HSM_DELETE_KEY = "hsm_ec_delete_key";
  public static final String HSM_LIST_KEYS = "hsm_list_keys";
  public static final String SESSION_END = "session_end";
  public static final String SESSION_CONTEXT_END = "session_context_end";
  public static final String STORE = "store";
  public static final String RETRIEVE = "retrieve";
  public static final String LOG = "log";
  public static final String GET_LOG = "get_log";
  public static final String INFO = "info";
}

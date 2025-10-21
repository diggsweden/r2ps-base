package se.digg.wallet.r2ps.commons.dto.servicetype;

import jakarta.annotation.Nonnull;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;

import java.util.HashMap;
import java.util.Map;

/**
 * Registry for service types
 *
 */
public class ServiceTypeRegistry {

  Map<String, ServiceType> serviceTypes;

  public ServiceTypeRegistry() {
    this.serviceTypes = new HashMap<>();
    registerServiceType(ServiceType.AUTHENTICATE, EncryptOption.DEVICE);
    registerServiceType(ServiceType.PIN_REGISTRATION, EncryptOption.DEVICE);
    registerServiceType(ServiceType.PIN_CHANGE, EncryptOption.USER);
    registerServiceType(ServiceType.HSM_ECDSA, EncryptOption.USER);
    registerServiceType(ServiceType.HSM_ECDH, EncryptOption.USER);
    registerServiceType(ServiceType.HSM_KEYGEN, EncryptOption.USER);
    registerServiceType(ServiceType.HSM_DELETE_KEY, EncryptOption.USER);
    registerServiceType(ServiceType.HSM_LIST_KEYS, EncryptOption.USER);
    registerServiceType(ServiceType.SESSION_END, EncryptOption.DEVICE);
    registerServiceType(ServiceType.SESSION_CONTEXT_END, EncryptOption.DEVICE);
    registerServiceType(ServiceType.STORE, EncryptOption.USER);
    registerServiceType(ServiceType.RETRIEVE, EncryptOption.USER);
    registerServiceType(ServiceType.LOG, EncryptOption.USER);
    registerServiceType(ServiceType.GET_LOG, EncryptOption.USER);
    registerServiceType(ServiceType.INFO, EncryptOption.USER);
  }

  @Nonnull
  public ServiceType getServiceType(String id) {
    ServiceType serviceType = serviceTypes.get(id);
    if (serviceType == null) {
      throw new IllegalArgumentException(
          String.format("Request for unrecognized service type %s", id));
    }
    return serviceType;
  }

  public void registerServiceType(ServiceType serviceType) {
    this.serviceTypes.put(serviceType.id(), serviceType);
  }

  public void registerServiceType(String id, EncryptOption encryptKey) {
    ServiceType serviceType = new ServiceType(id, encryptKey);
    this.registerServiceType(serviceType);
  }

}

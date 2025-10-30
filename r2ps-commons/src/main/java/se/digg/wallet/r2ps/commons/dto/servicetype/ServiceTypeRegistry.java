package se.digg.wallet.r2ps.commons.dto.servicetype;

import jakarta.annotation.Nonnull;
import java.util.HashMap;
import java.util.Map;
import se.digg.wallet.r2ps.commons.dto.EncryptOption;

/** Registry for service types */
public class ServiceTypeRegistry {

  Map<String, ServiceType> serviceTypes;

  public ServiceTypeRegistry() {
    this.serviceTypes = new HashMap<>();
    registerServiceType(ServiceType.AUTHENTICATE, EncryptOption.device);
    registerServiceType(ServiceType.PIN_REGISTRATION, EncryptOption.device);
    registerServiceType(ServiceType.PIN_CHANGE, EncryptOption.user);
    registerServiceType(ServiceType.HSM_ECDSA, EncryptOption.user);
    registerServiceType(ServiceType.HSM_ECDH, EncryptOption.user);
    registerServiceType(ServiceType.HSM_KEYGEN, EncryptOption.user);
    registerServiceType(ServiceType.HSM_DELETE_KEY, EncryptOption.user);
    registerServiceType(ServiceType.HSM_LIST_KEYS, EncryptOption.user);
    registerServiceType(ServiceType.SESSION_END, EncryptOption.device);
    registerServiceType(ServiceType.SESSION_CONTEXT_END, EncryptOption.device);
    registerServiceType(ServiceType.STORE, EncryptOption.user);
    registerServiceType(ServiceType.RETRIEVE, EncryptOption.user);
    registerServiceType(ServiceType.LOG, EncryptOption.user);
    registerServiceType(ServiceType.GET_LOG, EncryptOption.user);
    registerServiceType(ServiceType.INFO, EncryptOption.user);
  }

  /**
   * Retrieves the {@link ServiceType} associated with the specified ID.
   *
   * @param id the unique identifier for the service type to retrieve
   * @return the {@link ServiceType} corresponding to the given ID
   * @throws IllegalArgumentException if the specified ID does not correspond to a recognized
   *     service type
   */
  @Nonnull
  public ServiceType getServiceType(String id) {
    ServiceType serviceType = serviceTypes.get(id);
    if (serviceType == null) {
      throw new IllegalArgumentException(
          String.format("Request for unrecognized service type %s", id));
    }
    return serviceType;
  }

  /**
   * Registers a new service type in the registry.
   *
   * @param serviceType the {@link ServiceType} to be registered
   */
  public void registerServiceType(ServiceType serviceType) {
    this.serviceTypes.put(serviceType.id(), serviceType);
  }

  /**
   * Removes a service type from the registry.
   *
   * @param id the unique identifier of the service type to be removed
   */
  public void removeServiceType(String id) {
    this.serviceTypes.remove(id);
  }

  /**
   * Removes all service types from the registry.
   *
   * <p>This method clears all entries in the internal map of service types, leaving the registry
   * empty.
   */
  public void removeAllServiceTypes() {
    this.serviceTypes.clear();
  }

  public void registerServiceType(String id, EncryptOption encryptKey) {
    ServiceType serviceType = new ServiceType(id, encryptKey);
    this.registerServiceType(serviceType);
  }
}

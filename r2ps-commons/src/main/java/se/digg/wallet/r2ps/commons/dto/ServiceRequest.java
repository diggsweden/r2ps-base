package se.digg.wallet.r2ps.commons.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Objects;

@EqualsAndHashCode(callSuper = true)
@Data
public class ServiceRequest extends ServiceExchange {

  @JsonProperty("client_id")
  private String clientID;

  @JsonProperty("kid")
  private String kid;

  @JsonProperty("context")
  private String context;

  /** The type of service exchange which determines the content of serviceData */
  @JsonProperty("type")
  private String serviceType;

  @JsonProperty("pake_session_id")
  private String pakeSessionId;

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder extends AbstractBuilder<ServiceRequest, Builder> {

    public Builder() {
      super(new ServiceRequest());
    }

    @Override
    protected Builder getBuilder() {
      return this;
    }

    @Override
    protected void validate() {
      Objects.requireNonNull(this.serviceExchange.getClientID(), "The client ID is not set");
      Objects.requireNonNull(this.serviceExchange.getKid(), "The key identifier is not set");
      Objects.requireNonNull(this.serviceExchange.getServiceType(),
          "The exchange service type is not set");
    }

    public Builder clientID(final String clientID) {
      this.serviceExchange.setClientID(clientID);
      return this;
    }

    public Builder pakeSessionId(final String pakeSessionId) {
      this.serviceExchange.setPakeSessionId(pakeSessionId);
      return this;
    }

    public Builder kid(final String kid) {
      this.serviceExchange.setKid(kid);
      return this;
    }

    public Builder context(final String context) {
      this.serviceExchange.setContext(context);
      return this;
    }

    public Builder serviceType(final String serviceType) {
      this.serviceExchange.setServiceType(serviceType);
      return this;
    }

  }


}

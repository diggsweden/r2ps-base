package se.digg.wallet.r2ps.commons.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class ServiceResponse extends ServiceExchange {

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder extends AbstractBuilder<ServiceResponse, Builder> {

    public Builder() {
      super(new ServiceResponse());
    }

    @Override
    protected Builder getBuilder() {
      return this;
    }

    @Override
    protected void validate() {}
  }
}

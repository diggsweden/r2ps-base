package se.digg.wallet.r2ps.client.api;

import se.digg.wallet.r2ps.commons.dto.HttpResponse;

public interface ServiceExchangeConnector {

  HttpResponse requestService(String serviceRequest);
}

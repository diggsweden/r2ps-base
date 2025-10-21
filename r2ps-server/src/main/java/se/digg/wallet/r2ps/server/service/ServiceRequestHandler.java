package se.digg.wallet.r2ps.server.service;

import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;

public interface ServiceRequestHandler {
  String handleServiceRequest(String serviceRequest) throws ServiceRequestHandlingException;
}

package se.digg.wallet.r2ps.server.service;

import se.digg.wallet.r2ps.commons.dto.HttpResponse;
import se.digg.wallet.r2ps.commons.exception.ServiceRequestHandlingException;

public interface ServiceRequestDispatcher {

  HttpResponse dispatchServiceRequest(String serviceRequest, String context)
      throws ServiceRequestHandlingException;

  boolean supports(String context);
}

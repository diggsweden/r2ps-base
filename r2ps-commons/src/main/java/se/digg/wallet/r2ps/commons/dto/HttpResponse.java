package se.digg.wallet.r2ps.commons.dto;

/**
 * Encapsulates the HTTP response data received from a service request. This record is utilized to
 * store and access the response data and HTTP status code returned by a service exchange mechanism.
 *
 * <p>The {@code responseData} contains the body of the HTTP response, which could be JSON,
 * plaintext, or other supported formats, depending on the service's API.
 *
 * <p>The {@code responseCode} represents the HTTP status code returned by the service. It provides
 * information about the result of the HTTP request, with common status codes such as 200 (OK) for
 * success and others for different error or informational states.
 */
public record HttpResponse(String responseData, int responseCode) {}

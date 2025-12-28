package burp.api.montoya.http;

/**
 * Redirection modes when sending a request.
 */
public enum RedirectionMode
{
    /**
     * Always follow redirects.
     */
    ALWAYS,
    /**
     * Never follow redirects.
     */
    NEVER,
    /**
     * Only follow redirects to the same host.
     */
    SAME_HOST,
    /**
     * Only follow redirects if the redirect location is in scope.
     */
    IN_SCOPE
}

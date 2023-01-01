namespace OAuthGrantExchangeIntegration;

public class OAuthGrantExchangeConsts
{
    public const string TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
    public const string TOKEN_TYPE_REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token";
    public const string TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    public const string TOKEN_TYPE_SAML1 = "urn:ietf:params:oauth:token-type:saml1";
    public const string TOKEN_TYPE_SAML2 = "urn:ietf:params:oauth:token-type:saml2";

    public const string GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

    public const string ERROR_INVALID_REQUEST = "invalid_request";
    public const string ERROR_INVALID_CLIENT = "invalid_client";
    public const string ERROR_INVALID_GRANT = "invalid_grant";
    public const string ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client";
    public const string ERROR_UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public const string ERROR_INVALID_SCOPE = "invalid_scope";

    // https://datatracker.ietf.org/doc/html/rfc8693#name-request
    public const string REQUEST_GRANT_TYPE = "grant_type";
    public const string REQUEST_RESOURCE = "resource";
    public const string REQUEST_AUDIENCE = "audience";
    public const string REQUEST_SUBJECT_TOKEN_TYPE = "subject_token_type";
    public const string REQUEST_SUBJECT_TOKEN = "subject_token";
    public const string REQUEST_REQUESTED_TOKEN_TYPE = "requested_token_type";
    public const string REQUEST_ACTOR_TOKEN = "actor_token";
    public const string REQUEST_ACTOR_TOKEN_TYPE = "actor_token_type";
    public const string SCOPE = "scope";

    // https://datatracker.ietf.org/doc/html/rfc8693#name-response
    public const string RESPONSE_ACCESS_TOKEN = "access_token";
    public const string RESPONSE_ISSUED_TOKEN_TYPE = "issued_token_type";
    public const string RESPONSE_TOKEN_TYPE = "token_type";
    public const string RESPONSE_EXPIRES_IN = "expires_in";
    public const string RESPONSE_REFRESH_TOKEN = "refresh_token";

    // https://www.rfc-editor.org/rfc/rfc6749#section-5.2
    public const string RESPONSE_ERROR = "error";
    public const string RESPONSE_ERROR_DESCRIPTION = "error_description";
    public const string RESPONSE_ERROR_URI = "error_uri";

    // extra claims in error response but not in spec
    public const string RESPONSE_ERROR_CODES = "error_codes";
    public const string RESPONSE_ERROR_TIMESTAMP = "timestamp";
    public const string RESPONSE_ERROR_TRACE_ID = "trace_id";
    public const string RESPONSE_ERROR_CORRELATION_ID = "correlation_id";
    public const string RESPONSE_ERROR_CLAIMS = "claims";

}

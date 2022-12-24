﻿namespace OAuthGrantExchangeIntegration;

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
}

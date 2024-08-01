package org.fikua.keycloak.oidc4vci.service;

import org.fikua.model.AuthorizationServerMetadata;
import org.fikua.model.CredentialIssuerMetadata;
import org.fikua.model.CredentialOffer;
import org.fikua.model.TokenResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.ErrorResponseException;

public interface Oidc4vciService {
    CredentialIssuerMetadata buildCredentialIssuerMetadata();
    AuthorizationServerMetadata buildOAuth2AuthorizationServerMetadata();
    String buildCredentialOffer(String vcType);
    CredentialOffer getCredentialOfferById(String id) throws ErrorResponseException;
    void verifyTxCode(String txCode, String preAuthorizedCode);
    TokenResponse buildTokenResponse(KeycloakSession session, String preAuthorizedCode);
}

package org.fikua.keycloak.oidc4vci.service;

import org.fikua.model.CredentialOffer;

public interface OIDC4VCIService {
    CredentialOffer buildCredentialOffer(String vcType);
}

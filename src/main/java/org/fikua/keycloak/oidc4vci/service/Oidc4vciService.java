package org.fikua.keycloak.oidc4vci.service;

import org.fikua.model.CredentialOffer;

public interface Oidc4vciService {
    CredentialOffer buildCredentialOffer(String vcType);
}

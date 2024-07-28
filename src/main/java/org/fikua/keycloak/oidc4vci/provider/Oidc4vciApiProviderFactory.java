package org.fikua.keycloak.oidc4vci.provider;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@Slf4j
public class Oidc4vciApiProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "vci";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        log.info("Creating Oidc4vciApiProvider");
        return new Oidc4vciApiProvider(session);
    }

    @Override
    public void init(Config.Scope scope) {
        log.info("Initializing Oidc4vciApiProviderFactory");
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        log.info("Post Initializing Oidc4vciApiProviderFactory");
    }

    @Override
    public void close() {
        log.info("Closing Oidc4vciApiProviderFactory");
    }

    @Override
    public String getId() {
        return ID;
    }

}

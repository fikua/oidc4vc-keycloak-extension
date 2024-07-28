package org.fikua.keycloak.config;

import java.util.concurrent.TimeUnit;

public class KeycloakConfig {

    private KeycloakConfig() {
        throw new IllegalStateException("Utility class");
    }

    public static String getAuthServerUrl() {
        return System.getenv("KEYCLOAK_AUTH_SERVER_URL");
    }

    public static String getRealm() {
        return System.getenv("KEYCLOAK_REAL");
    }

    /**
     * Gets the environment variable ISSUER_API_URL from the docker-compose environment
     */
    public static String getIssuerUrl() {
        return System.getenv("ISSUER_API_URL");
    }

    /**
     * Obtains the environment variable ISSUER_API_EXTERNAL_URL from the docker-compose environment
     */
    public static String getIssuerExternalUrl() {
        return System.getenv("ISSUER_API_EXTERNAL_URL");
    }

    /**
     * Obtains the environment variable PRE_AUTH_LIFESPAN from the docker-compose environment
     */
    public static long getPreAuthLifespan() {
        return Long.parseLong(System.getenv("PRE_AUTH_LIFESPAN"));
    }

    /**
     * Obtains the environment variable PRE_AUTH_LIFESPAN_TIME_UNIT from the docker-compose environment
     */
    public static TimeUnit getPreAuthLifespanTimeUnit() {
        return TimeUnit.valueOf(System.getenv("PRE_AUTH_LIFESPAN_TIME_UNIT").toUpperCase());
    }

    /**
     * Obtains the environment variable TX_CODE_SIZE from the docker-compose environment
     */
    public static int getTxCodeSize() {
        return Integer.parseInt(System.getenv("TX_CODE_SIZE"));
    }

    /**
     * Obtains the environment variable TX_CODE_DESCRIPTION from the docker-compose environment
     */
    public static String getTxCodeDescription() {
        return System.getenv("TX_CODE_DESCRIPTION");
    }

    /**
     * Obtains the environment variable TOKEN_EXPIRATION (in seconds) from the docker-compose environment
     */
    public static int getTokenExpiration() {
        return Integer.parseInt(System.getenv("TOKEN_EXPIRATION"));
    }

}

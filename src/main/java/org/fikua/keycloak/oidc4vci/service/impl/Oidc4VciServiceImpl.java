package org.fikua.keycloak.oidc4vci.service.impl;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import lombok.extern.slf4j.Slf4j;
import org.fikua.keycloak.oidc4vci.service.Oidc4vciService;
import org.fikua.model.CredentialOffer;
import org.fikua.model.PreAuthorizedCodeGrant;
import org.fikua.model.PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCode;
import org.fikua.model.PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode;

import java.security.SecureRandom;
import java.util.List;

import static org.fikua.keycloak.config.KeycloakConfig.*;
import static org.fikua.keycloak.oidc4vci.util.Oidc4vciUtils.generateCustomNonce;

@Slf4j
public class Oidc4VciServiceImpl implements Oidc4vciService {

    private Cache<String, String> cache;

    public Oidc4VciServiceImpl() {
        initializeCache();
    }

    public CredentialOffer buildCredentialOffer(String vcType) {
        CredentialOffer credentialOffer = new CredentialOffer();
        // Credential Issuer reefers to the URL of the issuer accessible from the client (externally)
        credentialOffer.setCredentialIssuer(getIssuerExternalUrl());
        // Credential Configuration Ids refers to the list of supported credentials that
        credentialOffer.setCredentialConfigurationIds(List.of(vcType));
        // Build grants
        PreAuthorizedCodeGrant preAuthorizedCodeGrant = new PreAuthorizedCodeGrant();
        preAuthorizedCodeGrant.setUrnColonIetfColonParamsColonOauthColonGrantTypeColonPreAuthorizedCode(
                buildPreAuthorizedCodeGrant()
        );
        // Set grants in CredentialOffer
        credentialOffer.setGrants(preAuthorizedCodeGrant);
        return credentialOffer;
    }

    private PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCode buildPreAuthorizedCodeGrant() {
        // Build and store pre-authorized_code value
        String preAuthorizedCodeValue = generatePreAuthorizedCode();
        cache.put(preAuthorizedCodeValue, preAuthorizedCodeValue);
        // Build and store tx_code value
        String txCodeValue = generateTxCodeValue();
        cache.put(preAuthorizedCodeValue, txCodeValue);
        // Build tx_code object
        PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode txCode =
                new PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCodeTxCode()
                        .inputMode("numeric")
                        .length(getTxCodeSize())
                        .description(getTxCodeDescription());
        // Build pre-authorized_code grant object
        return new PreAuthorizedCodeGrantUrnIetfParamsOauthGrantTypePreAuthorizedCode()
                .preAuthorizedCode(preAuthorizedCodeValue)
                .txCode(txCode);
    }

    private String generatePreAuthorizedCode() {
        return generateCustomNonce();
    }

    public String generateTxCodeValue() {
        SecureRandom random = new SecureRandom();
        int codeSize = getTxCodeSize();
        double minValue = Math.pow(10, (double) codeSize - 1);
        double maxValue = Math.pow(10, codeSize) - 1;
        // Generate a random number within the specified range.
        return String.valueOf(random.nextInt((int) (maxValue - minValue + 1)) + (int) minValue);
    }

    private synchronized void initializeCache() {
        if (cache == null) {
            cache = CacheBuilder.newBuilder()
                    .expireAfterWrite(getPreAuthLifespan(), getPreAuthLifespanTimeUnit())
                    .concurrencyLevel(Runtime.getRuntime().availableProcessors())
                    .build();
        }
    }

}

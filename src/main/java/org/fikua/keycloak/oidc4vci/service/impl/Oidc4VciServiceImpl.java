package org.fikua.keycloak.oidc4vci.service.impl;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.fikua.keycloak.config.KeycloakConfig;
import org.fikua.keycloak.oidc4vci.service.Oidc4vciService;
import org.fikua.model.*;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.services.ErrorResponseException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.fikua.keycloak.config.KeycloakConfig.*;
import static org.fikua.keycloak.oidc4vci.util.Oidc4vciUtils.generateCustomNonce;

@Slf4j
public class Oidc4VciServiceImpl implements Oidc4vciService {

    private static final Cache<String, Object> cache = CacheBuilder.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .concurrencyLevel(Runtime.getRuntime().availableProcessors())
            .build();

    public String buildCredentialOffer(String vcType) {
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
        // Build Credential Offer URI
        String credentialOfferId = generateCustomNonce();
        cache.put(credentialOfferId, credentialOffer);
        return buildCredentialOfferUri(credentialOfferId);
    }

    public CredentialOffer getCredentialOfferById(String id) throws ErrorResponseException {
        CredentialOffer credentialOfferFound = (CredentialOffer) cache.getIfPresent(id);
        if(credentialOfferFound != null) {
            log.info("Credential Offer found: {}", credentialOfferFound);
            cache.invalidate(id);
            return credentialOfferFound;
        } else {
            throw new ErrorResponseException(Response
                    .status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse().error(ErrorResponse.ErrorEnum.INVALID_OR_MISSING_CREDENTIAL_OFFER))
                    .build());
        }
    }

    public CredentialIssuerMetadata buildCredentialIssuerMetadata() {
        // Build Credential Configuration Supported Map
        Map<String, CredentialConfiguration> credentialConfigurationSupported = new HashMap<>();
        // Credential Configuration Supported for LEARCredentialEmployee
        CredentialConfiguration learCredentialEmployeeCredentialConfiguration = new CredentialConfiguration();
        // Format
        learCredentialEmployeeCredentialConfiguration.setFormat(VcFormat.JWT_VC_JSON);
        // Scope
        learCredentialEmployeeCredentialConfiguration.setScope(VcType.LEAR_CREDENTIAL_EMPLOYEE);
        // cryptographic_binding_methods_supported
        learCredentialEmployeeCredentialConfiguration.setCryptographicBindingMethodsSupported(
                List.of(CredentialConfiguration.CryptographicBindingMethodsSupportedEnum.DID_KEY));
        // credential_signing_alg_values_supported
        learCredentialEmployeeCredentialConfiguration.setCredentialSigningAlgValuesSupported(
                List.of(SignatureAlgorithm.ES256.getValue()));
        // proof_types_supported
        ProofTypeValue proofTypeValue = new ProofTypeValue();
        proofTypeValue.setProofSigningAlgValuesSupported(List.of(SignatureAlgorithm.ES256));
        learCredentialEmployeeCredentialConfiguration.setProofTypesSupported(
                Map.of(ProofType.JWT.getValue(), proofTypeValue));
        // vct
        learCredentialEmployeeCredentialConfiguration.setVct("LEARCredentialEmployee");
        // claims
//        ClaimsDisplayObjectValue mantadorClaims = new ClaimsDisplayObjectValue();
//        ClaimsDisplayObjectValue mandateeClaims = new ClaimsDisplayObjectValue();



        learCredentialEmployeeCredentialConfiguration.setClaims(
                Map.of("mandator", new ClaimsDisplayObjectValue()));

        credentialConfigurationSupported.put("LEARCredentialEmployee", learCredentialEmployeeCredentialConfiguration);
        // Credential Configuration Supported for VerifiableCertification
        CredentialConfiguration verifiableCertificatioCredentialConfiguration = new CredentialConfiguration();
        verifiableCertificatioCredentialConfiguration.setFormat(VcFormat.JWT_VC_JSON);
        verifiableCertificatioCredentialConfiguration.setScope(VcType.VERIFIABLE_CERTIFICATION);
        // credential_signing_alg_values_supported
        verifiableCertificatioCredentialConfiguration.setCredentialSigningAlgValuesSupported(
                List.of(SignatureAlgorithm.ES256.getValue()));
        verifiableCertificatioCredentialConfiguration.setVct("VerifiableCertification");

//        verifiableCertificatioCredentialConfiguration.setClaims(
//                Map.of());

        credentialConfigurationSupported.put("VerifiableCertification", verifiableCertificatioCredentialConfiguration);
        // Build Credential Issuer Metadata object
        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata();
        credentialIssuerMetadata.setCredentialIssuer(KeycloakConfig.getIssuerExternalUrl());
        credentialIssuerMetadata.setCredentialEndpoint(KeycloakConfig.getIssuerExternalUrl() + "/credential");
        credentialIssuerMetadata.setCredentialConfigurationsSupported(credentialConfigurationSupported);
        return credentialIssuerMetadata;
    }

    public AuthorizationServerMetadata buildOAuth2AuthorizationServerMetadata() {
        AuthorizationServerMetadata authorizationServerMetadata = new AuthorizationServerMetadata();
        authorizationServerMetadata.setPreAuthorizedGrantAnonymousAccessSupported(true);
        return authorizationServerMetadata;
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

    private String buildCredentialOfferUri(String credentialOfferId) {
        String credentialOfferUri = getIssuerExternalUrl() + "/credential-offer/" + credentialOfferId;
        URLEncoder.encode(credentialOfferUri, StandardCharsets.UTF_8);
        return "openid-credential-offer://?credential_offer_uri=" +
                getIssuerExternalUrl() +
                "/vci/credential-offer/" +
                credentialOfferId;
    }

}

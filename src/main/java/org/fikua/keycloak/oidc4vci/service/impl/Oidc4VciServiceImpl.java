package org.fikua.keycloak.oidc4vci.service.impl;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.fikua.keycloak.config.KeycloakConfig;
import org.fikua.keycloak.oidc4vci.service.Oidc4vciService;
import org.fikua.model.*;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.math.BigDecimal;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
        VcType learCredentialEmployeeType = VcType.LEAR_CREDENTIAL_EMPLOYEE;
        VcType verifiableCertificationType = VcType.VERIFIABLE_CERTIFICATION;
        // Build Credential Configuration Supported Map
        Map<String, CredentialConfiguration> credentialConfigurationSupported = new HashMap<>();
        // Credential Configuration Supported for LEARCredentialEmployee
        CredentialConfiguration learCredentialEmployeeCredentialConfiguration =
                buildLEARCredentialEmployeeCredentialConfiguration(learCredentialEmployeeType);
        credentialConfigurationSupported.put(learCredentialEmployeeType.getValue(),
                learCredentialEmployeeCredentialConfiguration);
        // Credential Configuration Supported for VerifiableCertification
        CredentialConfiguration verifiableCertificatioCredentialConfiguration =
                buildVerifiableCertificationCredentialConfiguration(verifiableCertificationType);
        credentialConfigurationSupported.put(verifiableCertificationType.getValue(),
                verifiableCertificatioCredentialConfiguration);
        // Build Credential Issuer Metadata object
        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata();
        credentialIssuerMetadata.setCredentialIssuer(KeycloakConfig.getIssuerExternalUrl());
        credentialIssuerMetadata.setCredentialEndpoint(KeycloakConfig.getIssuerExternalUrl() + "/credential");
        credentialIssuerMetadata.setCredentialConfigurationsSupported(credentialConfigurationSupported);
        return credentialIssuerMetadata;
    }

    /**
     * If the provided tx_code don't match with the one bounded with the pre-authorized_code in cache throw error.
     *
     * @param txCode            - tx_code
     * @param preAuthorizedCode - pre-authorized_code
     */
    public void verifyTxCode(String txCode, String preAuthorizedCode) {
        if (!Objects.equals(cache.getIfPresent(preAuthorizedCode), txCode)) {
            cache.invalidate(preAuthorizedCode);
            throw new ErrorResponseException(Response
                    .status(Response.Status.NOT_FOUND)
                    .entity(new ErrorResponse().error(ErrorResponse.ErrorEnum.INVALID_TX_CODE))
                    .build());
        }
    }

    public TokenResponse buildTokenResponse(KeycloakSession session, String preAuthorizedCode) {
        // Build EventBuilder
        EventBuilder eventBuilder = new EventBuilder(session.getContext().getRealm(), session,
                session.getContext().getConnection());
        // Parse the pre-authorized_code
        OAuth2CodeParser.ParseResult result = OAuth2CodeParser.parseCode(session, preAuthorizedCode,
                session.getContext().getRealm(), eventBuilder);
        // Check if the code is expired or illegal
        checkIfCodeIsExpiredOrIllegal(result);
        // Set the realm and client in the session context
        session.getContext().setRealm(result.getClientSession().getRealm());
        session.getContext().setClient(result.getClientSession().getClient());
        // Create the client access token
        AccessToken accessToken = new TokenManager().createClientAccessToken(session,
                result.getClientSession().getRealm(),
                result.getClientSession().getClient(),
                result.getClientSession().getUserSession().getUser(),
                result.getClientSession().getUserSession(),
                DefaultClientSessionContext.fromClientSessionAndScopeParameter(result.getClientSession(),
                        OAuth2Constants.SCOPE_OPENID, session));
        // setting custom expiration time from env variables
        accessToken.exp((long) (getTokenExpiration() + Time.currentTime()));
        String encryptedToken = session.tokens().encodeAndEncrypt(accessToken);

        // todo: review new issuer flow
//        sendPreAuthCodeAndAccessTokenToIssuer(preAuthorizedCode, encryptedToken);

        // Build c_nonce and c_nonce_expires_in
        long expiresIn = accessToken.getExp() - Time.currentTime();
        String nonce = generateCustomNonce();
        cache.put(nonce, nonce);

        // Build and return TokenResponse
        return getTokenResponse(encryptedToken, expiresIn, nonce);
    }

    private static TokenResponse getTokenResponse(String encryptedToken, long expiresIn, String nonce) {
        long nonceExpiresIn = (int) TimeUnit.SECONDS.convert(getPreAuthLifespan(), getPreAuthLifespanTimeUnit());
        // Build Authorization Details
        TokenResponseAuthorizationDetailsInner learCredentialEmployeeAuthorizationDetails = new TokenResponseAuthorizationDetailsInner();
        learCredentialEmployeeAuthorizationDetails.type("openid_credential");
        learCredentialEmployeeAuthorizationDetails.credentialConfigurationId("LEARCredentialEmployee");
        TokenResponseAuthorizationDetailsInner verifiableCertificationAuthorizationDetails = new TokenResponseAuthorizationDetailsInner();
        verifiableCertificationAuthorizationDetails.type("openid_credential");
        verifiableCertificationAuthorizationDetails.credentialConfigurationId("VerifiableCertification");
        // Build and return TokenResponse
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken(encryptedToken);
        tokenResponse.setTokenType(TokenResponse.TokenTypeEnum.BEARER);
        tokenResponse.setExpiresIn(BigDecimal.valueOf(expiresIn));
        tokenResponse.setcNonce(nonce);
        tokenResponse.setcNonceExpiresIn(BigDecimal.valueOf(nonceExpiresIn));
        tokenResponse.setAuthorizationDetails(List.of(
                learCredentialEmployeeAuthorizationDetails,
                verifiableCertificationAuthorizationDetails));
        return tokenResponse;
    }

    private void checkIfCodeIsExpiredOrIllegal(OAuth2CodeParser.ParseResult result) {
        if (result.isExpiredCode() || result.isIllegalCode()) {
            throw new ErrorResponseException(Response
                    .status(Response.Status.BAD_REQUEST)
                    .entity(new ErrorResponse()
                            .error(ErrorResponse.ErrorEnum.INVALID_TOKEN)
                            .message("Invalid pre-authorized_code"))
                    .build());
        }
    }

    private CredentialConfiguration buildLEARCredentialEmployeeCredentialConfiguration(VcType vcType) {
        // Credential Configuration Supported for LEARCredentialEmployee
        CredentialConfiguration learCredentialEmployeeCredentialConfiguration;
        learCredentialEmployeeCredentialConfiguration = getCredentialConfiguration(vcType);
        // cryptographic_binding_methods_supported
        learCredentialEmployeeCredentialConfiguration.setCryptographicBindingMethodsSupported(
                List.of(CredentialConfiguration.CryptographicBindingMethodsSupportedEnum.DID_KEY));
        // proof_types_supported
        ProofTypeValue proofTypeValue = new ProofTypeValue();
        proofTypeValue.setProofSigningAlgValuesSupported(List.of(SignatureAlgorithm.ES256));
        learCredentialEmployeeCredentialConfiguration.setProofTypesSupported(
                Map.of(ProofType.JWT.getValue(), proofTypeValue));
        // claims
        // add credential claims - optional for now
        return learCredentialEmployeeCredentialConfiguration;
    }

    private CredentialConfiguration buildVerifiableCertificationCredentialConfiguration(VcType vcType) {
        // claims
        // add credential claims - optional for now
        return getCredentialConfiguration(vcType);
    }

    private CredentialConfiguration getCredentialConfiguration(VcType vcType) {
        CredentialConfiguration verifiableCertificatioCredentialConfiguration = new CredentialConfiguration();
        verifiableCertificatioCredentialConfiguration.setFormat(VcFormat.JWT_VC_JSON);
        verifiableCertificatioCredentialConfiguration.setScope(vcType);
        // credential_signing_alg_values_supported
        verifiableCertificatioCredentialConfiguration.setCredentialSigningAlgValuesSupported(
                List.of(SignatureAlgorithm.ES256.getValue()));
        // vct
        verifiableCertificatioCredentialConfiguration.setVct(vcType.getValue());
        return verifiableCertificatioCredentialConfiguration;
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

        // todo: send email with tx_code to the user

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

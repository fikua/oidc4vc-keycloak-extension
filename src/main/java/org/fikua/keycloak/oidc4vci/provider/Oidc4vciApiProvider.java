package org.fikua.keycloak.oidc4vci.provider;

import org.fikua.keycloak.oidc4vci.service.Oidc4vciService;
import org.fikua.keycloak.oidc4vci.service.impl.Oidc4VciServiceImpl;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.fikua.keycloak.config.KeycloakConfig;
import org.fikua.model.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.ErrorType;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.resource.RealmResourceProvider;

import java.util.Optional;

@Slf4j
@Path("vci")
public class Oidc4vciApiProvider implements RealmResourceProvider {

    public static final String ACCESS_CONTROL = "Access-Control-Allow-Origin";

    private final KeycloakSession session;

    private final Oidc4vciService oidc4VCIService = new Oidc4VciServiceImpl();

    public Oidc4vciApiProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        log.info("Closing Oidc4vciApiProvider");
    }

    @GET
    @Path(".well-known/openid-configuration")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAuthServerMetadata() {
        AuthorizationServerMetadata authorizationServerMetadata = new AuthorizationServerMetadata();
        authorizationServerMetadata.setPreAuthorizedGrantAnonymousAccessSupported(true);
        return Response.ok()
                .entity(authorizationServerMetadata)
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    @GET
    @Path(".well-known/openid-credential-issuer")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getCredentialIssuerMetadata() {
//        CredentialIssuerMetadataCredentialConfigurationsSupported credentialConfigurationsSupported = new CredentialIssuerMetadataCredentialConfigurationsSupported();
        // LEARCredentialEmployee Configuration Supported

        // VerifiableCertification Configuration Supported

        CredentialIssuerMetadata credentialIssuerMetadata = new CredentialIssuerMetadata();
        credentialIssuerMetadata.setCredentialIssuer(KeycloakConfig.getIssuerExternalUrl());
        credentialIssuerMetadata.setCredentialEndpoint(KeycloakConfig.getIssuerExternalUrl()+"/credential");
        // todo:
        // credentialIssuerMetadata.setCredentialConfigurationsSupported();

        return Response.ok()
                .entity(credentialIssuerMetadata)
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    @GET
    @Path("credential-offer")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getCredentialOffer(@QueryParam("type") String vcType, @QueryParam("format") String vcFormat) {
        // check if the provided type is supported
        VcType vcTypeResult = Optional.ofNullable(vcType).map(VcType::fromValue).orElseThrow(() ->
                new ErrorResponseException(getErrorResponse(ErrorType.valueOf("Invalid type"))));
        // check if the provided format is supported
        VcFormat vcFormatResult = Optional.ofNullable(vcFormat).map(VcFormat::fromValue).orElseThrow(() ->
                new ErrorResponseException(getErrorResponse(ErrorType.valueOf("Invalid format"))));
        log.debug("Get an offer for {} - {}", vcTypeResult, vcFormatResult);
        // Generate credential offer
        CredentialOffer credentialOffer = oidc4VCIService.buildCredentialOffer(vcType);
        return Response.ok()
                .entity(credentialOffer)
                .header(ACCESS_CONTROL, "*")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    private Response getErrorResponse(ErrorType errorType) {
        ErrorResponse.ErrorEnum errorEnum = ErrorResponse.ErrorEnum.fromValue(errorType.getValue());
        return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse().error(errorEnum))
                .build();
    }

}

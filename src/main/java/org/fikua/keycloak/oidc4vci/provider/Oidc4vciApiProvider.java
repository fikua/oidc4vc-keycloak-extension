package org.fikua.keycloak.oidc4vci.provider;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.fikua.keycloak.oidc4vci.service.Oidc4vciService;
import org.fikua.keycloak.oidc4vci.service.impl.Oidc4VciServiceImpl;
import org.fikua.model.ErrorResponse;
import org.fikua.model.TokenResponse;
import org.fikua.model.VcFormat;
import org.fikua.model.VcType;
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
    @Path("greetings")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getGreetings() {
        return Response.ok()
                .entity("Welcome to the OIDC4VCI API")
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    @GET
    @Path(".well-known/openid-configuration")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getAuthServerMetadata() {
        return Response.ok()
                .entity(oidc4VCIService.buildOAuth2AuthorizationServerMetadata())
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    @GET
    @Path(".well-known/openid-credential-issuer")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getCredentialIssuerMetadata() {
        return Response.ok()
                .entity(oidc4VCIService.buildCredentialIssuerMetadata())
                .header(ACCESS_CONTROL, "*")
                .build();
    }

    @GET
    @Path("credential-offer")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getCredentialOffer(@QueryParam("type") String vcType, @QueryParam("format") String vcFormat) {
        checkVcType(vcType);
        checkVcFormat(vcFormat);
        return Response.ok()
                .entity(oidc4VCIService.buildCredentialOffer(vcType))
                .header(ACCESS_CONTROL, "*")
                .type(MediaType.APPLICATION_JSON)
                .build();
    }

    @GET
    @Path("credential-offer/{id}")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getCredentialOfferById(@PathParam("id") String id) {
        try {
            return Response.ok()
                    .entity(oidc4VCIService.getCredentialOfferById(id))
                    .header(ACCESS_CONTROL, "*")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        } catch (ErrorResponseException e) {
            return Response.fromResponse(e.getResponse())
                    .entity(e.getResponse())
                    .header(ACCESS_CONTROL, "*")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    @POST
    @Path("token")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getToken(@FormParam("grant_type") String grantType,
                             @FormParam("pre-authorized_code") String preAuthorizedCode,
                             @FormParam("tx_code") String txCode) {
        try {
            // Verify GrantType is pre-authorized_code
            checkGrantType(grantType);
            // Verify tx_code
            oidc4VCIService.verifyTxCode(txCode, preAuthorizedCode);
            // Build Access Token and Token Response
            TokenResponse tokenResponse = oidc4VCIService.buildTokenResponse(session, preAuthorizedCode);
            return Response.ok().entity(tokenResponse)
                    .header(ACCESS_CONTROL, "*")
                    .header("Content-Type", MediaType.APPLICATION_JSON)
                    .build();
        } catch (ErrorResponseException e) {
            return Response.fromResponse(e.getResponse())
                    .entity(e.getResponse())
                    .header(ACCESS_CONTROL, "*")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }
    }

    private Response getErrorResponse(ErrorType errorType) {
        ErrorResponse.ErrorEnum errorEnum = ErrorResponse.ErrorEnum.fromValue(errorType.getValue());
        return Response
                .status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse().error(errorEnum))
                .build();
    }

    private void checkVcType(String vcType) {
        Optional.ofNullable(vcType).map(VcType::fromValue).orElseThrow(() ->
                new ErrorResponseException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_TYPE)));
    }

    private void checkVcFormat(String vcFormat) {
        Optional.ofNullable(vcFormat).map(VcFormat::fromValue).orElseThrow(() ->
                new ErrorResponseException(getErrorResponse(ErrorType.UNSUPPORTED_CREDENTIAL_FORMAT)));
    }

    private void checkGrantType(String grantType) {
        if (!"pre-authorized_code".equals(grantType)) {
            throw new ErrorResponseException(getErrorResponse(
                    ErrorType.valueOf(ErrorResponse.ErrorEnum.UNSUPPORTED_GRANT_TYPE.getValue())));
        }
    }

}

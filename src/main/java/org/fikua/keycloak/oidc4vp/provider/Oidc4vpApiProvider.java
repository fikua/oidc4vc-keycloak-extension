package org.fikua.keycloak.oidc4vp.provider;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;
import org.fikua.model.ErrorResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.ErrorType;
import org.keycloak.services.resource.RealmResourceProvider;

@Slf4j
@Path("vp")
public class Oidc4vpApiProvider implements RealmResourceProvider {

    public static final String ACCESS_CONTROL = "Access-Control-Allow-Origin";

    private final KeycloakSession session;

    public Oidc4vpApiProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        log.info("Closing Oidc4vpApiProvider");
    }

    @GET
    @Path("greetings")
    @Produces({MediaType.APPLICATION_JSON})
    public Response getGreetings() {
        return Response.ok()
                .entity("Welcome to the OIDC4VP API")
                .header(ACCESS_CONTROL, "*")
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

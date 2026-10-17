package dev.matura.keycloak;

import jakarta.ws.rs.core.Response;
import org.keycloak.OAuthErrorException;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;

import java.util.List;

/**
 * Adds tid, tenant, wid, troles, roles, perms (or perms_ref), ver and pmode to access tokens, from maturad
 * (technical specification §6). The tenant comes from the authorisation request parameter {@code matura_tenant}
 * (slug or id), else the one the user used last; the workspace from {@code matura_workspace}. A user outside the
 * tenant, or a tenant that has not enabled the app, gets {@code access_denied} with the reason as description.
 */
public class MaturaTokenMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {

    public static final String ID = "matura-token-mapper";
    static final String TENANT_NOTE = "client_request_param_matura_tenant";
    static final String WORKSPACE_NOTE = "client_request_param_matura_workspace";
    /** User-session note: when the mapper last issued a token in the session (Unix ms), for idle timeouts. */
    static final String LAST_USE_NOTE = "matura.last_token";

    private static volatile MaturaClient client;

    static MaturaClient client() {
        MaturaClient c = client;
        if (c == null) {
            synchronized (MaturaTokenMapper.class) {
                if (client == null) {
                    client = MaturaClient.fromEnv();
                }
                c = client;
            }
        }
        return c;
    }

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Matura tenant and permissions"; }
    @Override public String getDisplayCategory() { return TOKEN_MAPPER_CATEGORY; }
    @Override public String getHelpText() {
        return "Adds the Matura tenant, workspace, roles and permissions for this app to the access token.";
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        AuthenticatedClientSessionModel cs = clientSessionCtx.getClientSession();
        UserModel user = userSession.getUser();
        String name = String.join(" ", nz(user.getFirstName()), nz(user.getLastName())).trim();
        long lastUse = parseLong(userSession.getNote(LAST_USE_NOTE));
        MaturaClient.Request req = new MaturaClient.Request(user.getId(), user.getEmail(), user.isEmailVerified(), name,
                user.getFirstAttribute("locale"), cs.getClient().getClientId(), cs.getNote(TENANT_NOTE),
                cs.getNote(WORKSPACE_NOTE), userSession.getStarted() * 1000L, lastUse);
        MaturaClient.Answer answer;
        try {
            answer = client().tokenContext(req);
        } catch (Exception e) {
            // fail closed: no token without Matura's say
            throw new ErrorResponseException(OAuthErrorException.TEMPORARILY_UNAVAILABLE,
                    "matura_unavailable", Response.Status.SERVICE_UNAVAILABLE);
        }
        if (answer.refused()) {
            if ("session_expired".equals(answer.refusal())) {
                // the tenant's session limits are over: end the SSO session so the next sign-in asks again
                session.sessions().removeUserSession(session.getContext().getRealm(), userSession);
            }
            throw new ErrorResponseException(OAuthErrorException.ACCESS_DENIED, answer.refusal(), Response.Status.FORBIDDEN);
        }
        userSession.setNote(LAST_USE_NOTE, Long.toString(System.currentTimeMillis()));
        MaturaClaims.apply(token, answer.claims());
        return token;
    }

    private static long parseLong(String s) {
        try {
            return s == null ? 0 : Long.parseLong(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static String nz(String s) { return s == null ? "" : s; }
}

package dev.matura.keycloak;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.AbstractIdpAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.PostBrokerLoginConstants;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Guards sign-ins through a tenant's identity provider (TS13). In the first-login flow, before Keycloak creates or
 * links an account, it asks maturad whether the asserted email is in a domain the provider's tenant verified, so a
 * tenant's IdP can never take over someone else's address. In the post-login flow it asks again with the user id,
 * and maturad adds the user to the tenant if needed (just-in-time membership).
 */
public class MaturaSsoAuthenticator implements Authenticator {

    static SerializedBrokeredIdentityContext brokered(AuthenticationSessionModel authSession) {
        SerializedBrokeredIdentityContext ctx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                authSession, PostBrokerLoginConstants.PBL_BROKERED_IDENTITY_CONTEXT);
        if (ctx == null) {
            ctx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(
                    authSession, AbstractIdpAuthenticator.BROKERED_CONTEXT_NOTE);
        }
        return ctx;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        SerializedBrokeredIdentityContext ctx = brokered(context.getAuthenticationSession());
        if (ctx == null) {
            context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
            return;
        }
        UserModel user = context.getUser();
        String email = user != null && user.getEmail() != null ? user.getEmail() : ctx.getEmail();
        String name = String.join(" ", nz(ctx.getFirstName()), nz(ctx.getLastName())).trim();
        MaturaClient.Answer answer;
        try {
            if (user != null && ctx.getEmail() != null && !ctx.getEmail().equalsIgnoreCase(email)) {
                // the IdP now asserts another address than the account's: both must be in the tenant's domains
                MaturaClient.Answer first = MaturaTokenMapper.client().ssoLogin(ctx.getIdentityProviderId(),
                        ctx.getEmail(), null, name);
                if (first.refused()) {
                    refuse(context, first);
                    return;
                }
            }
            answer = MaturaTokenMapper.client().ssoLogin(ctx.getIdentityProviderId(), email,
                    user == null ? null : user.getId(), name);
        } catch (Exception e) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form()
                    .setError("Sign-in is unavailable right now. Try again in a minute.")
                    .createErrorPage(Response.Status.SERVICE_UNAVAILABLE));
            return;
        }
        if (answer.refused()) {
            refuse(context, answer);
            return;
        }
        context.success();
    }

    private static void refuse(AuthenticationFlowContext context, MaturaClient.Answer answer) {
        String message = answer.detail() == null || answer.detail().equals("null")
                ? "Your organisation's identity provider cannot sign in this account." : answer.detail();
        context.failure(AuthenticationFlowError.ACCESS_DENIED, context.form().setError(message)
                .createErrorPage(Response.Status.FORBIDDEN));
    }

    private static String nz(String s) { return s == null ? "" : s; }

    @Override public void action(AuthenticationFlowContext context) { context.success(); }
    @Override public boolean requiresUser() { return false; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}

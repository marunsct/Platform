package dev.matura.keycloak;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

import java.util.List;

/**
 * Enforces tenant MFA policies (TS12). It runs after the password and the conditional second-factor step of
 * Matura's browser flow, and in the post-login flow of social identity providers. It asks maturad whether the user
 * belongs to a tenant whose security policy requires MFA; if so and the user has no second factor yet, it adds the
 * required action that enrols one (TOTP by default), so the sign-in cannot finish without it. Users who already have
 * a second factor were challenged for it by the step before. If maturad cannot be reached, sign-in fails (closed).
 */
public class MaturaMfaPolicyAuthenticator implements Authenticator {

    /** Credential types that count as a second factor and that Matura's flows challenge. */
    static final List<String> SECOND_FACTORS = List.of(OTPCredentialModel.TYPE,
            WebAuthnCredentialModel.TYPE_TWOFACTOR, WebAuthnCredentialModel.TYPE_PASSWORDLESS);

    private final String enrolAction;

    MaturaMfaPolicyAuthenticator(String enrolAction) {
        this.enrolAction = enrolAction;
    }

    static boolean hasSecondFactor(UserModel user) {
        return SECOND_FACTORS.stream().anyMatch(t -> user.credentialManager().isConfiguredFor(t));
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null) {
            context.attempted();
            return;
        }
        boolean required;
        try {
            required = MaturaTokenMapper.client().mfaRequired(user.getId());
        } catch (Exception e) {
            context.failure(AuthenticationFlowError.INTERNAL_ERROR, context.form()
                    .setError("Sign-in is unavailable right now. Try again in a minute.")
                    .createErrorPage(Response.Status.SERVICE_UNAVAILABLE));
            return;
        }
        if (required && !hasSecondFactor(user)) {
            context.getAuthenticationSession().addRequiredAction(enrolAction);
        }
        context.success();
    }

    @Override public void action(AuthenticationFlowContext context) { context.success(); }
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}

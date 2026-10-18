package dev.matura.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/** Registers {@link MaturaMfaPolicyAuthenticator} as {@code matura-mfa-policy}. */
public class MaturaMfaPolicyAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "matura-mfa-policy";
    private String enrolAction = UserModel.RequiredAction.CONFIGURE_TOTP.name();

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Matura MFA policy"; }
    @Override public String getReferenceCategory() { return "mfa"; }
    @Override public String getHelpText() {
        return "Requires a second factor when one of the user's Matura tenants requires MFA; enrols one if missing.";
    }
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }

    @Override public Authenticator create(KeycloakSession session) { return new MaturaMfaPolicyAuthenticator(enrolAction); }

    /** SPI option {@code --spi-authenticator--matura-mfa-policy--enrol-action}: e.g. webauthn-register. */
    @Override public void init(Config.Scope config) {
        String v = config.get("enrolAction");
        if (v != null && !v.isBlank()) {
            enrolAction = v;
        }
    }
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}

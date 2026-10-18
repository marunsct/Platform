package dev.matura.keycloak;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/** Registers {@link MaturaSsoAuthenticator} as {@code matura-sso}. */
public class MaturaSsoAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "matura-sso";

    @Override public String getId() { return ID; }
    @Override public String getDisplayType() { return "Matura tenant SSO"; }
    @Override public String getReferenceCategory() { return "matura-sso"; }
    @Override public String getHelpText() {
        return "Accepts identity-provider sign-ins only for the tenant's verified email domains and adds the user to the tenant.";
    }
    @Override public boolean isConfigurable() { return false; }
    @Override public boolean isUserSetupAllowed() { return false; }
    @Override public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.DISABLED};
    }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
    @Override public Authenticator create(KeycloakSession session) { return new MaturaSsoAuthenticator(); }
    @Override public void init(Config.Scope config) {}
    @Override public void postInit(KeycloakSessionFactory factory) {}
    @Override public void close() {}
}

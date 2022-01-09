package com.keycloak.authentication.browser;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

import static org.keycloak.authentication.forms.RegistrationRecaptcha.*;

public class RecaptchaAuthenticatorFactory extends UsernamePasswordFormFactory {

    protected static final String MAX_FAILURE_CONFIG_NAME = "maxFailures";
    private final RecaptchaAuthenticator SINGLETON = new RecaptchaAuthenticator();

    public static final String PROVIDER_ID = "recaptcha-username-password-form";

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };


    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;


        property = new ProviderConfigProperty();
        property.setName(MAX_FAILURE_CONFIG_NAME);
        property.setLabel("Max Login Failures");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("4");
        property.setHelpText("How many failures before the reCaptcha showed.");
        CONFIG_PROPERTIES.add(property);


        property = new ProviderConfigProperty();
        property.setName(SITE_KEY);
        property.setLabel("Recaptcha Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google Recaptcha Site Key");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(SITE_SECRET);
        property.setLabel("Recaptcha Secret");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Google Recaptcha Secret");
        CONFIG_PROPERTIES.add(property);

        property = new ProviderConfigProperty();
        property.setName(USE_RECAPTCHA_NET);
        property.setLabel("use recaptcha.net");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Use recaptcha.net? (or else google.com)");
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public String getDisplayType() {
        return "Recaptcha";
    }


    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "If the user provides fault credentials more than the given time, adds Google Recaptcha button. Recaptchas verify that the entity that is registering is a human.  This can only be used on the internet and must be configured after you add it.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

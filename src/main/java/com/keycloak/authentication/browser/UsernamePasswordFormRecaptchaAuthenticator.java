package com.keycloak.authentication.browser;

import com.keycloak.authentication.AuthenticatorUtil;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.LoginBean;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.util.*;

import static com.keycloak.authentication.browser.UsernamePasswordFormRecaptchaAuthenticatorFactory.MAX_FAILURE_CONFIG_NAME;
import static org.keycloak.authentication.forms.RegistrationRecaptcha.*;


public class UsernamePasswordFormRecaptchaAuthenticator extends UsernamePasswordForm {

    private static final Logger logger = Logger.getLogger(UsernamePasswordFormRecaptchaAuthenticator.class);
    private static final String RECAPTCHA_REQUIRED_AUTH_NOTE = "IsRecaptchaRequired";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
        String username = formData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (username != null) {

            UserModel user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username.trim());

            if (user != null) {

                if (isUserTemporarilyDisabled(context, user)) return;
                if (isRecaptchaRequired(context, user)) {

                    context.getAuthenticationSession().setAuthNote(RECAPTCHA_REQUIRED_AUTH_NOTE, "true");
                    if (Objects.nonNull(captcha)) {
                        if (!isRecaptchaValid(context, captcha)) {
                            logger.info("Recaptcha validation failed.");
                            Response failureChallenge = challenge(context, "Recaptcha validation failed.", null);
                            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, failureChallenge);
                            return;
                        }

                    } else {
                        context.forceChallenge(createUsernamePasswordWithRecaptchaLogin(context, context.form()));
                        return;
                    }
                }
            }
        }

        if (!validateForm(context, formData)) {
            return;
        }
        context.getEvent().detail(Details.REGISTER_METHOD, "form");
        context.success();
    }

    private boolean isUserTemporarilyDisabled(AuthenticationFlowContext context, UserModel user) {

        if (context.getRealm().isBruteForceProtected()) {
            if (context.getProtector().isTemporarilyDisabled(context.getSession(), context.getRealm(), user)) {

                Response challengeResponse = challenge(context, Messages.ACCOUNT_TEMPORARILY_DISABLED);
                context.failure(AuthenticationFlowError.USER_TEMPORARILY_DISABLED, challengeResponse);
                return true;
            }
        }
        return false;
    }

    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {

        LoginFormsProvider form = context.form()
                .setExecution(context.getExecution().getId());
        if (Objects.nonNull(error)) {
            if (Objects.nonNull(field)) {
                form.addError(new FormMessage(field, error));
            } else {
                form.setError(error);
            }
        }
        String isRecaptchaRequiredStr = context.getAuthenticationSession().getAuthNote(RECAPTCHA_REQUIRED_AUTH_NOTE);

        return "true".equals(isRecaptchaRequiredStr) ?
                createUsernamePasswordWithRecaptchaLogin(context, form) : createLoginForm(form);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        if (user == null) {
            logger.debug("Recaptcha wasn't required if no user provided.");
            return false;
        }
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }


    private boolean isRecaptchaValid(AuthenticationFlowContext context, String captcha) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String secret = captchaConfig.getConfig().get(SITE_SECRET);

        return !Validation.isBlank(captcha) && validateRecaptcha(context, captcha, secret);
    }

    private boolean isRecaptchaRequired(AuthenticationFlowContext context, UserModel user) {
        UserLoginFailureModel userLoginFailures = context.getSession().loginFailures().getUserLoginFailure(context.getRealm(), user.getId());

        int numberOfFailures = Objects.nonNull(userLoginFailures) ? userLoginFailures.getNumFailures() : 0;
        String maxFailure = AuthenticatorUtil.getConfigValue(context.getAuthenticatorConfig(), MAX_FAILURE_CONFIG_NAME, "4");

        return numberOfFailures >= Integer.valueOf(maxFailure);
    }


    private String getRecaptchaDomain(AuthenticatorConfigModel config) {
        Boolean useRecaptcha = Optional.ofNullable(config)
                .map(AuthenticatorConfigModel::getConfig)
                .map(cfg -> Boolean.valueOf(cfg.get(USE_RECAPTCHA_NET)))
                .orElse(false);
        if (useRecaptcha) {
            return "recaptcha.net";
        }

        return "google.com";
    }

    protected boolean validateRecaptcha(AuthenticationFlowContext context, String captcha, String secret) {

        CloseableHttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("https://www." + getRecaptchaDomain(context.getAuthenticatorConfig()) + "/recaptcha/api/siteverify");
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        boolean success = false;
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            try (CloseableHttpResponse response = httpClient.execute(post)) {
                InputStream content = response.getEntity().getContent();
                try {
                    Map json = JsonSerialization.readValue(content, Map.class);
                    Object val = json.get("success");
                    success = Boolean.TRUE.equals(val);
                } finally {
                    EntityUtils.consumeQuietly(response.getEntity());
                }
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }

    private Response createUsernamePasswordWithRecaptchaLogin(AuthenticationFlowContext context, LoginFormsProvider form) {

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        form.setAttribute("login", new LoginBean(formData));

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();
        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(SITE_KEY) == null
                || captchaConfig.getConfig().get(SITE_SECRET) == null
        ) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return form.createLoginUsernamePassword();
        }
        String siteKey = captchaConfig.getConfig().get(SITE_KEY);
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        form.addScript("https://www." + getRecaptchaDomain(captchaConfig) + "/recaptcha/api.js?hl=" + userLanguageTag);

        return form.createLoginUsernamePassword();
    }
}
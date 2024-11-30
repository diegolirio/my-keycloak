package io.github.diegolirio;

import jakarta.ws.rs.core.Response;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.email.DefaultEmailSenderProvider;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class EmailAuthenticator implements Authenticator , AuthenticatorFactory {

    private static final String TPL_CODE = "login-email.ftl";

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        System.out.println(">>>>>>>> authenticate \n\n\n");

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        KeycloakSession session = context.getSession();
        UserModel user = context.getUser();

        System.out.println(">>>>>>>> "+ user + "  \n\n\n");

        int length = Integer.parseInt(config.getConfig().get("length"));
        int ttl = Integer.parseInt(config.getConfig().get("ttl"));
        String subject = config.getConfig().get("subject");

        if(subject == null || subject.trim().isEmpty()) {
            subject = "Summit 2FA Code";
        }

        String code = "ABC123"; //org.keycloak.common.util. RandomString.randomCode(length);
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote("code", code);
        authSession.setAuthNote("ttl", Long.toString(System.currentTimeMillis() + (ttl * 1000L)));

        try {
            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
            Locale locale = session.getContext().resolveLocale(user);
            String emailAuthText = theme.getMessages(locale).getProperty("emailAuthText");
            String emailText = String.format(emailAuthText, code, Math.floorDiv(ttl, 60));

            DefaultEmailSenderProvider senderProvider = new DefaultEmailSenderProvider(session);
            senderProvider.send(
                    session.getContext().getRealm().getSmtpConfig(),
                    user,
                    subject,
                    emailText,
                    emailText
            );


            context.challenge(context.form().setAttribute("realm", context.getRealm()).createForm(TPL_CODE));
        } catch (Exception e) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("emailAuthEmailNotSent", e.getMessage())
                            .createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
        }
    }


    @Override
    public void action(AuthenticationFlowContext context) {
        System.out.println(">>>>>>>> action \n\n\n");
        String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String code = authSession.getAuthNote("code");
        String ttl = authSession.getAuthNote("ttl");

        if (code == null || ttl == null) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
            return;
        }

        boolean isValid = enteredCode.equals(code);
        if (isValid) {
            if (Long.parseLong(ttl) < System.currentTimeMillis()) {
                // expired
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                        context.form().setError("emailAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
            } else {
                // valid
                context.success();
            }
        } else {
            // invalid
            AuthenticationExecutionModel execution = context.getExecution();
            if (execution.isRequired()) {
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setAttribute("realm", context.getRealm())
                                .setError("emailAuthCodeInvalid").createForm(TPL_CODE));
            } else if (execution.isConditional() || execution.isAlternative()) {
                context.attempted();
            }
        }
        System.out.println(">>>>>>>> action \n\n\n");
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getEmail() != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "email-authenticator";
    }

    @Override
    public String getDisplayType() {
        return "Email Authentication";
    }

    @Override
    public String getHelpText() {
        return "Validates an OTP sent via EMAIL to the users email address.";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED,
        };
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Arrays.asList(
                new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
                new ProviderConfigProperty("ttl", "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
                new ProviderConfigProperty("senderId", "SenderId", "The sender ID is displayed as the message sender on the receiving device. (Not working!)", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
                new ProviderConfigProperty("subject", "E-Mail subject", "Subject for the email", ProviderConfigProperty.STRING_TYPE, "2FA Login Code")
        );
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new EmailAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }


}

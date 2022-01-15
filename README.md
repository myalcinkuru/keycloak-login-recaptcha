
# Keycloak Login Recaptcha

![Example Login Screen](https://github.com/muhammedyalcin/keycloak-login-recaptcha-by-condition/blob/main/screenshots/login-sc.gif?raw=true)
 
Keycloak supports the recaptcha in the registration flow but not in the login flow at this time. That's why this repository implements the conditional recaptcha execution  for the login flow.  The conditional recaptcha means that if the anyone tries to log-in already registered user with fault password, recaptcha being showed. `Max Login Failures`(How many failures before the reCaptcha showed) is configurable. To accomplish it, i extended the `UsernamePasswordForm` built-in keycloak execution. 


### Build With & Deploy To Keycloak

 1. This extension uses the gradle to compilation. To compile, navigate to repository and run below statement;

    `./gradlew clean assemble`
Not: The output is located as `build/libs/recaptcha-authenticator-1.0.jar`
2.  Copy output jar to keycloak's deployment folder for [hot deployment](https://www.keycloak.org/docs/latest/server_development/#using-the-keycloak-deployer). 


### Keycloak Configuration With Admin Console

1. There are some changes should be done in the theme. Assuming that you don't have any [custom theme](https://www.keycloak.org/docs/latest/server_development/#_theme_selector) (using keycloak theme) you might  edit the base theme (recommendation is creating your own theme).  We have already modified [login.ftl](https://github.com/muhammedyalcin/keycloak-login-recaptcha-by-condition/blob/main/resources/login.ftl)  file. You can directly copy and overwrite to path `keycloak/themes/base/login/login.ftl` or if any custom theme was used, take the diff with [login.ftl](https://github.com/muhammedyalcin/keycloak-login-recaptcha-by-condition/blob/main/resources/login.ftl)  file with `keycloak/themes/base/login/login.ftl` and then apply the changes to your custom `login.ftl`. 
2. Configure your login flow as below;
![Example Login Flow](https://github.com/muhammedyalcin/keycloak-login-recaptcha-by-condition/blob/main/screenshots/loginflow.png?raw=true)

3. Add config to  the Recaptcha execution by clicking the `Actions -> Config` 
![Recaptcha Execution Example Config](https://github.com/muhammedyalcin/keycloak-login-recaptcha-by-condition/blob/main/screenshots/recaptchaconfig.png?raw=true)

- Max Login Failures: How many failures before the reCaptcha showed.
- Recaptcha Site Key: Google Recaptcha Site Key
- Recaptcha Secret: Google Recaptcha Secret

4.  Navigate to `Realm Settings->Security Defenses`. Set  `X-Frame-Options` as `ALLOW-FROM https://www.google.com` and `Content-Security-Policy` as `frame-src 'self' https://www.google.com; frame-ancestors 'self'; object-src 'none';`
5. Enabled the brute force attack. [For detail](https://github.com/keycloak/keycloak-documentation/blob/main/server_admin/topics/threat/brute-force.adoc). If you already did that, no action needed. 

## Usage

There might be situations that requires to ask recaptcha if any account log-in  attempt failed like blocking to the attacker to guess that account password with bot. 
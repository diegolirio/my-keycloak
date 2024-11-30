# SPI Login OTP Send Mail

1. Project :: Create a new Project Java/Gradle
2. Project :: Add deps Keycloak in the Project
3. Project :: Set up Docker-Compose and Build with Make
4. Keycloak UI :: Add a email for the user admin
5. Keycloak UI :: Create a new Realm
6. Keycloak UI :: Realm Setting > Email, Configure Email SMTP in this new Realm
7. Keycloak UI :: Create a User e Client_id
8. Keycloak UI :: Authentication > Flows tab. Duplicate direct grant 
9. Keycloak UI :: Authentication > Flows tab. In OTP step change from conditional to required and click in + to add `Email Authentication` Step. 
10. Keycloak UI :: Authentication > Flows tab. Keep it in the first position on OPT direct grant as required
11. Keycloak UI :: Authentication > Flows tab. Click setting icon to fill the alias field, the name must be the same of the `id` project `email-authenticator`
12. Keycloak UI :: Authentication > Flows tab. In Action change the Bind Flow to Direct Grant Flow, as Principal.
13. 

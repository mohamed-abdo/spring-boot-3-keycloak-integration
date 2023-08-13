package com.keycloak.demo.custom;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class CustomClientRegistrationRepository implements ReactiveClientRegistrationRepository {
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @Override
    public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
        return Mono.just(keycloakClientRegistration());
    }

    public ClientRegistration keycloakClientRegistration() {
        return ClientRegistration
                .withRegistrationId("keycloak")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:8082/login/oauth2/code/callback")
                .scope("openid", "profile", "email")
                .authorizationUri("http://localhost:8080/realms/system/protocol/openid-connect/auth")
                .tokenUri("http://localhost:8080/realms/system/protocol/openid-connect/token")
                .userInfoUri("http://localhost:8080/realms/system/protocol/openid-connect/userinfo")
                .jwkSetUri("http://localhost:8080/realms/system/protocol/openid-connect/certs")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientName("Keycloak")
                .build();
    }
}

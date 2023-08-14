package com.keycloak.demo.custom;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
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
    @Value("${spring.security.oauth2.client.registration.keycloak.provider}")
    private String provider;
    @Value("${spring.security.oauth2.client.registration.keycloak.jwk-set-uri}")
    private String jwkSetUri;
    @Value("${spring.security.oauth2.client.registration.keycloak.user-info-uri}")
    private String userInfoUri;
    @Value("${spring.security.oauth2.client.registration.keycloak.token-uri}")
    private String tokenUri;
    @Value("${spring.security.oauth2.client.registration.keycloak.issuer-realm}")
    private String issuerRealm;
    @Value("${spring.security.oauth2.client.registration.keycloak.authorization-uri}")
    private String authorizationUri;
    @Value("${spring.security.oauth2.client.registration.keycloak.redirect-uri}")
    private String redirectUri;
    @Override
    public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
        return Mono.just(keycloakClientRegistration());
    }

    @Bean
    public ClientRegistration keycloakClientRegistration() {
        return ClientRegistration
                .withRegistrationId("keycloak")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri(redirectUri)
                .scope("openid", "profile", "email")
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .userInfoUri(userInfoUri)
                .jwkSetUri(jwkSetUri)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .clientName(provider)
                .build();
    }
}

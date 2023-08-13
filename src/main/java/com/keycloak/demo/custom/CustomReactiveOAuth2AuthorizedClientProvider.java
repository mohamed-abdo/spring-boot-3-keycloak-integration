package com.keycloak.demo.custom;

import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class CustomReactiveOAuth2AuthorizedClientProvider implements ReactiveOAuth2AuthorizedClientProvider {

    @Override
    public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context) {
        // Implement authorization logic for client_credentials grant type
        // This may involve requesting a token using the client credentials
        // For demonstration purposes, returning a placeholder authorized client
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                context.getClientRegistration(), context.getPrincipal().getName(),
                context.getAuthorizedClient().getAccessToken());
        return Mono.just(authorizedClient);
    }
}
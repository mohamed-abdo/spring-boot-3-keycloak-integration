package com.keycloak.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class OAuth2ClientController {

    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

    public OAuth2ClientController(ReactiveClientRegistrationRepository clientRegistrationRepository, ReactiveOAuth2AuthorizedClientService authorizedClientService) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/keycloak")
    public Mono<String> index() {
        return this.clientRegistrationRepository.findByRegistrationId("keycloak")
                .thenReturn("index");
    }

    @GetMapping("/token")
    public Mono<String> index(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken) {
            String clientId = "keycloak"; // Your client ID here
            return authorizedClientService.loadAuthorizedClient(clientId, authentication.getName())
                    .map(OAuth2AuthorizedClient::getAccessToken)
                    .map(AbstractOAuth2Token::getTokenValue)
                    .thenReturn("Access token is available.");
        } else {
            return Mono.empty(); // Or another appropriate Mono value
        }
    }

}
package com.keycloak.demo.custom;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;


@Slf4j
@Component
public class CustomReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication);
    }

    private static Authentication getAuthentication(Jwt jwt, Collection<? extends GrantedAuthority> authorities, OAuth2AuthenticationToken oauth2Authentication) {
        OAuth2AuthenticatedPrincipal principal = new CustomOAuth2AuthenticatedPrincipal(jwt.getClaims(), authorities);
        // Create an OAuth2User instance using a custom implementation
        OAuth2User oauth2User = new CustomOAuth2User(jwt.getClaims(), authorities);
        // Create a new OAuth2AuthenticationToken using OAuth2User as the principal
        Authentication newAuthentication = new OAuth2AuthenticationToken(oauth2User,
                authorities, oauth2Authentication.getAuthorizedClientRegistrationId());
        return newAuthentication;
    }

    private String extractClientIdFromJwt(Authentication authentication) {
        // Extract client ID from JWT claims based on your JWT structure
        // Return null if client ID is not found or invalid
        // Replace this with your actual JWT claims extraction logic
        // Example assumes "client_id" is a custom claim
        Object clientClaim = authentication.getPrincipal();
        return clientClaim != null ? clientClaim.toString() : null;
    }
}




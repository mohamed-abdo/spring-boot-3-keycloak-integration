package com.keycloak.demo.filter;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class CustomAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        // Add a custom header to the response
        var response = webFilterExchange.getExchange().getResponse();
        response.getHeaders().add("auth-header", "success");
        // Continue with the existing response content
        return response.setComplete();
    }
}

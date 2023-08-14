package com.keycloak.demo.filter;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CustomAuthenticationFailureHandler implements ServerAuthenticationEntryPoint, ServerAuthenticationFailureHandler {

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange exchange, AuthenticationException exception) {
        // Handle authentication failure logic here
        ServerWebExchange serverWebExchange = exchange.getExchange();
        // Handle the failure and respond accordingly
        serverWebExchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        serverWebExchange.getResponse().getHeaders().add("auth-failed", "failed");
        // override the response content
        var responseBody = "Forbidden access!";
        return serverWebExchange.getResponse().writeWith(Mono.just(serverWebExchange.getResponse()
                .bufferFactory().wrap(responseBody.getBytes())));
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        // Customize the response, e.g., set custom headers or modify the status code
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().set("auth-failed", "Failure");
        exchange.getResponse().writeWith(Mono.empty());
        return Mono.empty();
    }
}
package com.keycloak.demo.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.time.Instant;

@Slf4j
@Component
public class CustomResponseHeaderFilter implements WebFilter, Ordered {

    private static final int FILTER_ORDER = Ordered.HIGHEST_PRECEDENCE;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        // Interception before reaching the controller
        log.info("Interception before reaching the controller :: {}", Instant.now());
        ServerHttpRequest request = exchange.getRequest();
        // You can modify the request here if needed
        return chain.filter(exchange)
                .then(Mono.defer(() -> {
                    // Interception after the controller
                    log.info("Interception after the controller :: {}", Instant.now());
                    ServerHttpResponse response = exchange.getResponse();
                    // Add a custom header to the response
                    return Mono.empty();
                }));
    }

    @Override
    public int getOrder() {
        return FILTER_ORDER;
    }
}

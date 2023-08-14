package com.keycloak.demo.filter;

import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class CustomResponseHeaderFilter implements WebFilter, Ordered {

    private static final int FILTER_ORDER = Ordered.HIGHEST_PRECEDENCE;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange).then(Mono.defer(() -> {
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


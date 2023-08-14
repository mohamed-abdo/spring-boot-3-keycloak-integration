package com.keycloak.demo.config;

import com.keycloak.demo.custom.CustomClientRegistrationRepository;
import com.keycloak.demo.custom.CustomReactiveAuthenticationManager;
import com.keycloak.demo.filter.CustomAuthenticationFailureHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.reactive.config.EnableWebFlux;

@Configuration
@EnableWebFlux
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfiguration {

    @Autowired
    ServerAuthenticationConverter authenticationConverter;
    @Autowired
    ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
    @Autowired
    CustomAuthenticationFailureHandler failureHandler;
    @Autowired
    AuthenticationWebFilter authenticationWebFilter;
    @Autowired
    CustomReactiveAuthenticationManager authenticationManager;
    @Autowired
    CustomClientRegistrationRepository clientRegistrationRepository;
    @Autowired
    ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
    @Autowired
    ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange((authorize) -> authorize
                        .anyExchange().authenticated()
                )
                .httpBasic(Customizer.withDefaults())
                .oauth2Client(oauth2 -> oauth2
                        .clientRegistrationRepository(this.clientRegistrationRepository)
                        .authorizedClientRepository(this.authorizedClientRepository)
                        .authorizationRequestRepository(this.authorizationRequestRepository)
                        .authorizationRequestResolver(this.authorizationRequestResolver)
                        .authenticationConverter(this.authenticationConverter)
                        .authenticationManager(authenticationManager)
                )
                .addFilterAt(this.authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling(exceptionHandlingSpec -> exceptionHandlingSpec.authenticationEntryPoint(failureHandler));
        return http.build();
    }


}

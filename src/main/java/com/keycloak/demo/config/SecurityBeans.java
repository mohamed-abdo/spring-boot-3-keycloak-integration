package com.keycloak.demo.config;

import com.keycloak.demo.custom.CustomReactiveAuthenticationManager;
import com.keycloak.demo.custom.CustomServerAuthorizationRequestRepository;
import com.keycloak.demo.filter.CustomAuthenticationFailureHandler;
import com.keycloak.demo.filter.CustomAuthenticationSuccessHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.*;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.function.Consumer;
import java.util.function.Function;

@Slf4j
@Configuration
public class SecurityBeans {
    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Autowired
    ClientRegistration keycloakClientRegistration;

    @Bean
    public ReactiveClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryReactiveClientRegistrationRepository(this.keycloakClientRegistration);
    }

    @Bean
    public ServerAuthorizationRequestRepository serverAuthorizationRequestRepository() {
        return new CustomServerAuthorizationRequestRepository();
    }

    @Bean
    public ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }

    @Bean
    public AuthenticationWebFilter authenticationFilter(CustomReactiveAuthenticationManager customAuthenticationManager, CustomAuthenticationFailureHandler customAuthenticationFailureHandler) {
        AuthenticationWebFilter authenticationFilter = new AuthenticationWebFilter(customAuthenticationManager);
        authenticationFilter.setAuthenticationFailureHandler(customAuthenticationFailureHandler);
        return authenticationFilter;
    }

    @Bean
    public ServerAuthenticationConverter serverAuthenticationConverter(CustomReactiveAuthenticationManager customReactiveAuthenticationManager) {
        return exchange -> {
            // Extract client ID from JWT claims based on your JWT structure
            // Create an Authentication object (JwtAuthenticationToken)
            var token = extractTokenFromRequest(exchange);
            if (Objects.isNull(token)) {
                Collection<GrantedAuthority> anonymousAuthorities = AuthorityUtils.createAuthorityList("anonymous_user");
                return customReactiveAuthenticationManager.authenticate(new AnonymousAuthenticationToken("anonymous-user", new Object(), anonymousAuthorities));
            }
            var jwt = validateAndParseToken(token);
            var authentication = new JwtAuthenticationToken(jwt);
            log.info("authentication :: {}", authentication);
            var oauth = createOAuth2AuthenticationTokenFromJwt(jwt);
            return customReactiveAuthenticationManager.authenticate(oauth);
        };
    }

    @Bean
    public AuthenticationWebFilter authenticationWebFilter(ServerAuthenticationConverter authenticationConverter) {
        AuthenticationWebFilter filter = new AuthenticationWebFilter(
                new CustomReactiveAuthenticationManager()); // Implement this manager

        //filter.setAuthenticationSuccessHandler(successHandler());
        filter.setServerAuthenticationConverter(authenticationConverter);

        return filter;
    }

    @Bean
    public CustomAuthenticationSuccessHandler successHandler() {
        return new CustomAuthenticationSuccessHandler();
    }

    @Bean
    public CustomAuthenticationFailureHandler failureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        // Customize the authorities extraction if needed
        // converter.setJwtGrantedAuthoritiesConverter(...);
        return converter;
    }

    @Bean
    public ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        DefaultServerOAuth2AuthorizationRequestResolver authorizationRequestResolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(
                        clientRegistrationRepository);
        authorizationRequestResolver.setAuthorizationRequestCustomizer(
                authorizationRequestCustomizer());

        return authorizationRequestResolver;
    }

    private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
        return customizer -> customizer
                .additionalParameters(params -> params.put("prompt", "consent"));
    }

    private Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper() {
        return authorizeRequest -> {
            Map<String, Object> contextAttributes = Collections.emptyMap();
            ServerWebExchange exchange = authorizeRequest.getAttribute(ServerWebExchange.class.getName());
            ServerHttpRequest request = exchange.getRequest();
            String username = request.getQueryParams().getFirst(OAuth2ParameterNames.USERNAME);
            String password = request.getQueryParams().getFirst(OAuth2ParameterNames.PASSWORD);
            if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
                contextAttributes = new HashMap<>();

                // `PasswordReactiveOAuth2AuthorizedClientProvider` requires both attributes
                contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
                contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
            }
            return Mono.just(contextAttributes);
        };
    }

    public OAuth2AuthenticationToken createOAuth2AuthenticationTokenFromJwt(Jwt jwt) {
        var authorities = extractAuthoritiesFromClaims(jwt.getClaims());

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, jwt.getTokenValue(),
                jwt.getIssuedAt(), jwt.getExpiresAt());

        // You can create more complex UserDetails or OAuth2User implementations
        Map<String, Object> attributes = jwt.getClaims();
        OAuth2User oAuth2User = new DefaultOAuth2User(authorities, attributes, "sub");

        OAuth2RefreshToken refreshToken = null; // Set refresh token if needed

        Authentication oauth2Authentication = new OAuth2AuthenticationToken(oAuth2User, authorities, clientId);

        return (OAuth2AuthenticationToken) oauth2Authentication;
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        return ReactiveJwtDecoders.fromIssuerLocation("http://localhost:8080/realms/system");
    }

    private Jwt validateAndParseToken(String token) {
        try {
            // Create a JwtDecoder
            JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation("http://localhost:8080/realms/system");
            // Decode the token
            Jwt jwt = jwtDecoder.decode(token);
            // Perform additional validation if needed
            return jwt;
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid token", e);
        }
    }

    private String extractTokenFromRequest(ServerWebExchange exchange) {
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); // Remove "Bearer " prefix
        }
        return null;
    }

    private Collection<? extends GrantedAuthority> extractAuthoritiesFromClaims(Map<String, Object> claims) {
        // Extract authorities/roles from claims and create a collection of GrantedAuthority
        // For example, you might extract "roles" claim and convert them to SimpleGrantedAuthority
        // Return an empty list if no authorities are found
        // This is just a basic example, adjust as per your JWT claims structure
        // Make sure authorities are properly validated and sanitized
        // Ensure that roles are prefixed with "ROLE_" as per Spring Security conventions
        // Add proper error handling as needed

        // Example: Assuming "roles" claim is an array of roles
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (claims.containsKey("roles")) {
            List<String> roles = (List<String>) claims.get("roles");
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        }
        return authorities;
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

        ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
                ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .build();

        DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultReactiveOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    @Bean
    public ServerSecurityContextRepository serverSecurityContextRepository() {
        return NoOpServerSecurityContextRepository.getInstance();
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        return authorizationGrantRequest -> {
            OAuth2AccessTokenResponse tokenResponse = accessTokenResponseClient.getTokenResponse(authorizationGrantRequest);
            // Do any necessary customization with the token response here
            return tokenResponse;
        };
    }
}

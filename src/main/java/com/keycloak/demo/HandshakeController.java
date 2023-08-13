package com.keycloak.demo;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.util.Optional;

@RestController
@RequestMapping(value = "/handshake", consumes = {MediaType.ALL_VALUE}, produces = {MediaType.APPLICATION_JSON_VALUE})
public class HandshakeController {
    @GetMapping(value = {"", "/", "/{message}"})
    public Mono<String> handshake(@PathVariable(required = false, value = "message") Optional<String> message) {
        var msg = message.orElse("ok");
        if (msg.equalsIgnoreCase("throw-exception"))
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "hand_shake_throw_exception");
        return Mono.just(msg);
    }

    @GetMapping(value = {"login/oauth2/code/callback"})
    public Mono<String> callback(@RequestParam(required = false) Optional<String> message) {
        var msg = message.orElse("login-callback");
        return Mono.just(msg);
    }
}

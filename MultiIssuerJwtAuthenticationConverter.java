package com.mars.fakealbumsapi;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class MultiIssuerJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final Map<String, String> issuerJwksMap;


    //Angular App Auth Server => https://dev-58281825.okta.com/oauth2/default/v1/keys
    //API Server => https://dev-58281825.okta.com/oauth2/auso2htn7oWdgCFB75d7/v1/keys

    public MultiIssuerJwtAuthenticationConverter() {
        // Configure the issuer and JWKS URLs
        issuerJwksMap = Map.of(
                "https://dev-58281825.okta.com/oauth2/default",
                "https://dev-58281825.okta.com/oauth2/default/v1/keys",
                "https://dev-58281825.okta.com/oauth2/auso2htn7oWdgCFB75d7",
                "https://dev-58281825.okta.com/oauth2/auso2htn7oWdgCFB75d7/v1/keys"
        );
    }

    public Map<String, String> issuerJwksMap() {
        return issuerJwksMap;
    }

    @Override
    public JwtAuthenticationToken convert(Jwt jwt) {
        String issuer = jwt.getIssuer().toString();
        String jwksUrl = issuerJwksMap.get(issuer);

        if (jwksUrl == null) {
            throw new JwtException("Unsupported issuer: " + issuer);
        }

        JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuer);
        Jwt decodedJwt = jwtDecoder.decode(jwt.getTokenValue());

        Collection<GrantedAuthority> authorities = extractAuthorities(decodedJwt);
        //return new UsernamePasswordAuthenticationToken(decodedJwt.getSubject(), "n/a", authorities);
//        UsernamePasswordAuthenticationToken auth =
//                new UsernamePasswordAuthenticationToken(jwt.getSubject(), null, authorities);
//
//        // Store the Jwt as additional details
//        auth.setDetails(jwt);
       // return auth;
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        Object scopeClaim = jwt.getClaim("scp");
        if (scopeClaim != null) {
            // If 'scope' is a string (e.g., "read write admin")
            if (scopeClaim instanceof String) {
                Arrays.stream(((String) scopeClaim).split(" "))
                        .map(s -> new SimpleGrantedAuthority("SCOPE_" + s.trim()))
                        .forEach(authorities::add);
            }
            // If 'scope' is a list (e.g., ["read.api"])
            else if (scopeClaim instanceof List) {
                ((List<?>) scopeClaim).forEach(s -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + s.toString())));
            }
        }
        List<String> roles = jwt.getClaimAsStringList("groups");
        if (roles != null) {
            roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
        }

        System.out.println(authorities);
        return authorities;
    }
}
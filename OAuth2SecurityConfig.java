package com.mars.fakealbumsapi;

import com.nimbusds.jwt.SignedJWT;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.*;
import java.util.stream.Collectors;

/*
 * Server is set up with the following
 * 	- All requests are authenticated (they should have a valid token)
 * 	- All requests to /fakealbums/** must have scope of "photolibrary.read"
 * 	- tokens would be of JWT format
 * 	- No HttpSession will be created for a request. 
 * 
 * CHANGE : With Spring Boot 3.0, we no longer need to extend WebSecurityConfigurerAdapter
 */
@Configuration
public class OAuth2SecurityConfig {

    private final MultiIssuerJwtAuthenticationConverter multiIssuerJwtAuthenticationConverter;

    public OAuth2SecurityConfig(MultiIssuerJwtAuthenticationConverter multiIssuerJwtAuthenticationConverter) {
        this.multiIssuerJwtAuthenticationConverter = multiIssuerJwtAuthenticationConverter;
    }

	// CHANGE : With Spring Boot 3.0, Create a SecurityFilterChain 
	@Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
          .cors(Customizer.withDefaults())
          .authorizeHttpRequests(authz -> authz
            .requestMatchers("/jacksonville/**","/newyork/**","/miami/**","/random/**").permitAll()
            .requestMatchers("/api/protected-data").authenticated()
            .requestMatchers("/fakealbums/**").hasAuthority("SCOPE_photolibrary.read")
            .anyRequest().authenticated())
          //.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
          .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(multiIssuerJwtAuthenticationConverter))
          )
          .sessionManagement(sMgmt -> sMgmt.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        
        return http.build();
	}

    private Converter<Jwt,? extends AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(new Converter<Jwt, Collection<GrantedAuthority>>() {
            @Override
            public Collection<GrantedAuthority> convert(Jwt jwt) {
                List<GrantedAuthority> authorities = new ArrayList<>();

//                String clientId = jwt.getClaimAsString("client_id");
//                String azp = jwt.getClaimAsString("azp");
//                String issuer = jwt.getIssuer().toString();
//
//                // Example: Add roles based on client_id or azp
//                if ("frontend-client-id".equals(clientId)) {
//                    authorities.add(new SimpleGrantedAuthority("ROLE_FRONTEND"));
//                } else if ("mobile-client-id".equals(clientId)) {
//                    authorities.add(new SimpleGrantedAuthority("ROLE_MOBILE"));
//                }

                // 🔹 Extract 'scope' claim (usually a space-separated string)
                // 🔹 Extract 'scope' claim
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

                // Optional: add roles from a custom claim
                List<String> roles = jwt.getClaimAsStringList("roles");
                if (roles != null) {
                    roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())));
                }

                System.out.println(authorities);

                return authorities;
            }
        });
        return  converter;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        Map<String, JwtDecoder> decoders = multiIssuerJwtAuthenticationConverter.issuerJwksMap().keySet().stream()
                .collect(Collectors.toMap(
                        issuer -> issuer,
                        JwtDecoders::fromIssuerLocation
                ));

        return token -> {
            try {
                // Parse the JWT without verifying it
                SignedJWT signedJWT = SignedJWT.parse(token);
                String issuer = signedJWT.getJWTClaimsSet().getIssuer();

                JwtDecoder decoder = decoders.get(issuer);
                if (decoder == null) {
                    throw new JwtException("Unsupported issuer: " + issuer);
                }
                return decoder.decode(token);
            } catch (Exception e) {
                throw new JwtException("Failed to decode token: " + e.getMessage(), e);
            }
        };
    }

}

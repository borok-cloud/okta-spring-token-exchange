package com.mars.fakealbumsapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@RestController
@CrossOrigin
public class TokenExchangeController {

    //@Value("${okta.as1.client-id}")
    private String as1ClientId="0oao65xbtuKlciFp95d7";

    //@Value("${okta.as1.client-secret}")
    private String as1ClientSecret="XAlNlCV6V3eXoDRxy8fN3j7jHYQFcOG-V8LMNja-YZvfnE7ihD66noU6qsvqimLL";

    @Value("${okta.as1.token-url}")
    private String as1TokenUrl;

    @Value("${protected.resource.url}")
    private String protectedResourceUrl;

    private Logger logger = LoggerFactory.getLogger(TokenExchangeController.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/api/protected-data")
    public ResponseEntity<Object> getProtectedData(
            Authentication authentication,
            @RequestHeader("target-url") String targetUrl,
            @RequestHeader("Authorization") String uiToken
    ) throws Exception {
        //Jwt jwt = (Jwt) authentication.getDetails();
        String angularAccessToken = uiToken.split(" ")[1];
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
             Jwt jwt = jwtAuth.getToken();

            // ✅ Check if the token is authenticated (redundant but good practice)
            if (!jwtAuth.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated.");
            }

            // ✅ Check if token is expired
            Instant now = Instant.now();
            Instant expiresAt = jwt.getExpiresAt();

            if (expiresAt != null && expiresAt.isBefore(now)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expired.");
            }

            // ✅ Token is valid, continue
            String subject = jwt.getSubject();
            String email = (String) jwt.getClaims().get("email"); // Optional claim
            angularAccessToken = jwt.getTokenValue();

            //return ResponseEntity.ok("Authenticated as: " + subject + " | Email: " + email);
        }

//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + java.util.Base64.getEncoder().encodeToString((as1ClientId + ":" + as1ClientSecret).getBytes()));
//
//        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
//        map.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
//        map.add("subject_token", angularAccessToken);
//        map.add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
//        map.add("scope", "photolibrary.read");
//
//        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
//
//        ResponseEntity<String> response = restTemplate.postForEntity(as1TokenUrl, request, String.class);
//
//        try {
//            JsonNode jsonNode = objectMapper.readTree(response.getBody());
//            String apiAccessToken = jsonNode.get("access_token").asText();
//            return callProtectedResource(apiAccessToken);
//        } catch (Exception e) {
//            return ResponseEntity.badRequest().body("Error processing token exchange");
//        }
//        HttpHeaders headers = new HttpHeaders();
//        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
//        String basicAuth = Base64.getEncoder()
//                .encodeToString((as1ClientId + ":" + as1ClientSecret).getBytes(StandardCharsets.UTF_8));
//        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + basicAuth);

//        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
//        map.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
//        map.add("subject_token", angularAccessToken);
//        map.add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
//        map.add("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
//        map.add("scope", "photolibrary.read"); // Make sure this matches allowed scopes in AS1
//
//        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
//        String body = "grant_type=urn:ietf:params:oauth:grant-type:token-exchange"
//                + "&subject_token=" + angularAccessToken
//                + "&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
//                + "&requested_token_type=urn:ietf:params:oauth:token-type:access_token"
//                + "&scope=" + "photolibrary.read";
//
//        HttpEntity<String> request = new HttpEntity<>(body, headers);
//
//        try {
//            //ResponseEntity<String> response = restTemplate.postForEntity(as1TokenUrl, request, String.class);
//            ResponseEntity<String> response = restTemplate.exchange(
//                    as1TokenUrl, HttpMethod.POST, request, String.class);
//            return ResponseEntity.ok("Exchanged token response: " + response.getBody());
//        } catch (HttpClientErrorException e) {
//            //logger.error("Detaild Error exchanging token :", e.getResponseBodyAsString());
//            e.printStackTrace();
//            return ResponseEntity.status(e.getStatusCode())
//                    .body("Error exchanging token: " + e.getResponseBodyAsString());
//        }
        // Step 1: Generate EC key (P-256) for DPoP (should ideally be persisted)
        ECKey ecJwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint(true)
                .generate();
        try {
            ResponseEntity<String> response = TokenExchangeController.exchangeTokenWithDPoP(as1TokenUrl, as1ClientId, as1ClientSecret,
                    angularAccessToken, ecJwk,"https://api.server.com");
            String apiAccessToken = objectMapper.readTree(response.getBody()).get("access_token").asText();
            ResponseEntity<Object> apiResponse = DPoPApiCaller.callApiWithDpopToken(
                    targetUrl,
                    apiAccessToken,
                    ecJwk // Same key used in token exchange
            );
            return ResponseEntity.ok(apiResponse.getBody());
        }catch (HttpClientErrorException e) {
            //logger.error("Detaild Error exchanging token :", e.getResponseBodyAsString());
            e.printStackTrace();
            return ResponseEntity.status(e.getStatusCode())
                    .body("Error exchanging token: " + e.getResponseBodyAsString());
        }
    }

    private ResponseEntity<String> callProtectedResource(String apiAccessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + apiAccessToken);

        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> resourceResponse = restTemplate.getForEntity(protectedResourceUrl, String.class, request);
            return resourceResponse;
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error calling protected resource");
        }
    }

    public static ResponseEntity<String>  exchangeTokenWithDPoP(String tokenEndpointUrl, String clientId, String clientSecret,
                                               String subjectToken, ECKey ecJwk,String audience) throws Exception {



        RestTemplate restTemplate = new RestTemplate();
        URI tokenEndpoint = new URI(tokenEndpointUrl);

        // First attempt: no nonce
        String dpopProof = buildDpopJwt(tokenEndpoint, "POST", ecJwk, null);
        ResponseEntity<String> response;

        try {
            response = postTokenRequest(restTemplate, tokenEndpoint, clientId, clientSecret, subjectToken, audience, dpopProof);
            return response; // ✅ worked first time
        } catch (HttpClientErrorException ex) {
            // Check for nonce-required response
            String nonce = ex.getResponseHeaders().getFirst("DPoP-Nonce");
            if (nonce == null) throw ex;

            // Retry with nonce
            System.out.println("Received nonce, retrying with it: " + nonce);
            String newDpopProof = buildDpopJwt(tokenEndpoint, "POST", ecJwk, nonce);
            response = postTokenRequest(restTemplate, tokenEndpoint, clientId, clientSecret, subjectToken, audience, newDpopProof);
            return response;
        }
    }


    private static String buildDpopJwt(URI uri, String method, ECKey key, String nonce) throws Exception {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(Instant.now()))
                .claim("htu", uri.toString())
                .claim("htm", method);

        if (nonce != null) {
            claimsBuilder.claim("nonce", nonce);
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK())
                .build();

        SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private static ResponseEntity<String> postTokenRequest(RestTemplate restTemplate, URI tokenEndpoint,
                                                           String clientId, String clientSecret,
                                                           String subjectToken, String audience,
                                                           String dpopProof) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("DPoP", dpopProof);
        headers.setBasicAuth(clientId, clientSecret);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        form.add("subject_token", subjectToken);
        form.add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        form.add("audience", audience);
        form.add("scope", "photolibrary.read");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        return restTemplate.exchange(tokenEndpoint, HttpMethod.POST, request, String.class);
    }
}
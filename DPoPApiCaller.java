package com.mars.fakealbumsapi;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class DPoPApiCaller {

    public static ResponseEntity<Object> callApiWithDpopToken(String apiUrl, String accessToken, ECKey ecJwk) throws Exception {

        URI apiUri = new URI(apiUrl);
        String method = "GET";

        // Step 1: Build new DPoP proof for this API call
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(Instant.now()))
                .claim("htu", apiUri.toString())
                .claim("htm", method)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(ecJwk.toPublicJWK())
                .build();

        SignedJWT dpopJwt = new SignedJWT(header, claims);
        dpopJwt.sign(new ECDSASigner(ecJwk));

        String dpopProof = dpopJwt.serialize();

        // Step 2: Call downstream API
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);       // Authorization: Bearer <access_token>
        headers.set("DPoP", dpopProof);           // DPoP: <signed JWT>

        HttpEntity<Void> request = new HttpEntity<>(headers);
        RestTemplate restTemplate = new RestTemplate();
        try {
            ResponseEntity<Object> response = restTemplate.exchange(apiUri, HttpMethod.GET, request, Object.class);
            return response;
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }
}

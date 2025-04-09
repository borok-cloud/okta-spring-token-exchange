package com.mars.fakealbumsapi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Configuration
public class RestTemplateConfig {

    @Bean
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();

        // Adding logging interceptor
        ClientHttpRequestInterceptor loggingInterceptor = (request, body, execution) -> {
            System.out.println("Request URI: " + request.getURI());
            System.out.println("Headers: " + request.getHeaders());
            return execution.execute(request, body);
        };

        // Add the interceptor to the RestTemplate
        List<ClientHttpRequestInterceptor> interceptors = restTemplate.getInterceptors();
        interceptors.add(loggingInterceptor);
        restTemplate.setInterceptors(interceptors);

        return restTemplate;
    }
}

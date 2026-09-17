package com.lcwd.gateway.filter;

import com.lcwd.gateway.dto.TokenValidationResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;

/**
 * The single authentication boundary for requests entering through API Gateway.
 * It delegates signature, expiry, and user checks to JwtService; it does not
 * contain the signing secret and therefore fails closed when JwtService is down.
 */
@Component
public class JwtGatewayAuthenticationFilter extends OncePerRequestFilter {

    private final RestClient restClient;
    private final LoadBalancerClient loadBalancerClient;
    private final String jwtServiceId;

    public JwtGatewayAuthenticationFilter(LoadBalancerClient loadBalancerClient,
                                          @Value("${app.security.jwt-service-id}") String jwtServiceId) {
        this.restClient = RestClient.create();
        this.loadBalancerClient = loadBalancerClient;
        this.jwtServiceId = jwtServiceId;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Login must remain public so a caller can obtain its first token.

        return "OPTIONS".equalsIgnoreCase(request.getMethod())
                || "/auth/login".equals(request.getServletPath())
                || "/actuator/health".equals(request.getServletPath());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        System.out.println("authorization : "+ authorization);

        if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() <= 7) {
            writeError(response, HttpStatus.UNAUTHORIZED, "A Bearer token is required");
            return;
        }

        try {
            ServiceInstance jwtService = loadBalancerClient.choose(jwtServiceId);
            URI validationUri = UriComponentsBuilder.fromUri(jwtService.getUri())
                    .path("/auth/validate")
                    .build()
                    .toUri();
            TokenValidationResponse validation = restClient.post()
                    .uri(validationUri)
                    .header(HttpHeaders.AUTHORIZATION, authorization)
                    .retrieve()
                    .body(TokenValidationResponse.class);

            if (validation == null || !validation.valid()) {
                writeError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
                return;
            }
        } catch (RestClientResponseException exception) {
            if (exception.getStatusCode().is4xxClientError()) {
                writeError(response, HttpStatus.UNAUTHORIZED, "Invalid or expired token");
                return;
            }
            writeError(response, HttpStatus.SERVICE_UNAVAILABLE, "Authentication service is unavailable");
            return;
        } catch (RestClientException exception) {
            writeError(response, HttpStatus.SERVICE_UNAVAILABLE, "Authentication service is unavailable");
            return;
        } catch (RuntimeException exception) {
            // A discovery/client failure must not accidentally leave an endpoint open.
            writeError(response, HttpStatus.SERVICE_UNAVAILABLE, "Authentication service is unavailable");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void writeError(HttpServletResponse response, HttpStatus status, String message) throws IOException {
        response.setStatus(status.value());
        response.setContentType("application/json");
        response.getWriter().write("{\"status\":" + status.value() + ",\"error\":\"" + message + "\"}");
    }
}

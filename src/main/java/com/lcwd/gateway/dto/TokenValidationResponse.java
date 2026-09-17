package com.lcwd.gateway.dto;

/** Response returned by JwtService's internal token-validation endpoint. */
public record TokenValidationResponse(boolean valid, String username) {

}

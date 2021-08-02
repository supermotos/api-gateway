package com.scb.gateway.config;

import com.scb.gateway.dto.JwtParseRequestDto;
import com.scb.gateway.dto.JwtParseResponseDto;
import com.scb.gateway.util.HeaderMapRequestWrapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class AuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER = "Authorization";

    public static final String HEADER_VALUE_PREFIX = "Bearer";

    private static final String JWT_PARSE_URL = "http://auth-service/v1/jwt/parse";

    private final RestTemplate restTemplate;

    public AuthenticationFilter(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token = request.getHeader(HEADER);
        HeaderMapRequestWrapper wrappedRequest = new HeaderMapRequestWrapper((HttpServletRequest) request);
        if (token != null) {
            token = token.replace(HEADER_VALUE_PREFIX + " ", "");

            try {
                JwtParseResponseDto responseDto = parseJwt(token);
                wrappedRequest.addHeader("username", responseDto.getUsername());
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        responseDto.getUsername(),
                        null,
                        responseDto.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception ignore) {
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(wrappedRequest, response);
    }

    private JwtParseResponseDto parseJwt(String token) {
        JwtParseResponseDto responseDto = restTemplate.postForObject(JWT_PARSE_URL, new JwtParseRequestDto(token),
                JwtParseResponseDto.class);

        Objects.requireNonNull(responseDto);
        return responseDto;
    }
}
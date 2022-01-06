package com.wagner.springsecurityamigos.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Date;

@RequiredArgsConstructor(onConstructor=@__(@Autowired))
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest =
                    new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            Authentication authenticate = authenticationManager.authenticate(authentication);

            return authenticate;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }


    }

    // Método para enviar o token JWT para o cliente
    // Este método é invocado após o sucesso de attemptAuthentication()
    // se houver falha em attemptAuthentication(), este método não é invocado
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        String key = "assinatura_muito_segura_para_o_token_JWT";

        // CRIA O TOKEN JWT
        String tokenJwt = Jwts.builder()
                .setSubject(authResult.getName()) // O token jwt deve conter o nome do usuário
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date()) // data em que o token foi gerado
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusYears(1))) // token expira em um ano
                .signWith(Keys.hmacShaKeyFor(key.getBytes())) //gera a assinatura do token jwt
                .compact();

        // adiciona o token jwt no header do response
        response.addHeader("Authorization", "Bearer " + tokenJwt);
    }
}

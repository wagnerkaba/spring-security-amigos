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
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
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
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

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



        // CRIA O TOKEN JWT
        String tokenJwt = Jwts.builder()
                .setSubject(authResult.getName()) // O token jwt deve conter o nome do usuário
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date()) // data em que o token foi gerado
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays())))
                .signWith(secretKey) //gera a assinatura do token jwt
                .compact(); //Finally, we are compacting it into its final String form. A signed JWT is called a 'JWS'. (vide: https://github.com/jwtk/jjwt)

        // adiciona o token jwt no header do response
        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + tokenJwt);
    }
}

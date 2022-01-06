package com.wagner.springsecurityamigos.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.CookieManager;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@RequiredArgsConstructor(onConstructor=@__(@Autowired))
public class JwtTokenVerifier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;



    // FILTRO QUE ANALISA O TOKEN JWT DE CADA REQUEST
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // Captura o header
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        // se o header estiver vazio ou não tiver a palavra "Bearer ", o request será rejeitado
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {

            filterChain.doFilter(request, response);
            return;

        }

        // o authorizationHeader vem com a palavra "Bearer "
        // O comando abaixo retira a palavra "Bearer " para que o string "token" contenha apenas o token jwt
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try {

            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            // captura o body do token
            Claims tokensBody = claimsJws.getBody();

            // captura o username do token's body
            String username = tokensBody.getSubject();

            // captura a lista de authorities do token's body dentro da variavel authorities
            var authorities = (List<Map<String, String>>) tokensBody.get("authorities");

            // cria um set de SimpleGrantedAuthority através do mapeamento da variavel authorities
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);



        } catch (JwtException e){

            // se o token jwt não é válido, lança uma exceção
            throw new IllegalStateException("Token cannot be trusted: " + token);
        }


        // transmite o request e o response para o próximo filtro de segurança
        filterChain.doFilter(request, response);

    }
}

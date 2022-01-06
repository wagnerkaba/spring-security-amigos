package com.wagner.springsecurityamigos.jwt;
import com.google.common.net.HttpHeaders;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;


// cria arquivo de configuração para o jwt
// os valores estão armazenados em application.properties


@NoArgsConstructor
@Getter
@Setter
@ConfigurationProperties(prefix = "application.jwt")
@Configuration
public class JwtConfig {

    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;

    public String getAuthorizationHeader(){
        return HttpHeaders.AUTHORIZATION;
    }



}

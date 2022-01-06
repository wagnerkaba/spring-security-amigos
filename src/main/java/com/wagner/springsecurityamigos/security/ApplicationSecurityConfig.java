package com.wagner.springsecurityamigos.security;


import com.wagner.springsecurityamigos.auth.ApplicationUserService;
import com.wagner.springsecurityamigos.jwt.JwtTokenVerifier;
import com.wagner.springsecurityamigos.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static com.wagner.springsecurityamigos.security.ApplicationUserPermission.COURSE_WRITE;
import static com.wagner.springsecurityamigos.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor(onConstructor=@__(@Autowired))
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    private final ApplicationUserService applicationUserService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//               SE DEIXAR CSRF HABILITADO, O SPRING GERA UM TOKEN CSRF QUE É GRAVADO EM UM COOKIE
//               E QUE TEM QUE SER RETORNADO EM QUALQUER REQUEST
//                https://docs.spring.io/spring-security/site/docs/5.0.x/reference/html/csrf.html

                .csrf().disable()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) //JWT é stateless
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager())) //filtro utilizado quando o usuário tenta se autenticar
                .addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class) //filtro para verificar se o token jwt é válido
                .authorizeRequests()
                .antMatchers("/**", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();


//=================================================================================================================
//              ATENÇÃO A ORDEM EM QUE .antMatchers é colocada é importante.
//              vide explicação em   https://www.youtube.com/watch?v=her_7pa0vrg
//              no seguinte trecho: 1:48:37 - ORDER DOES MATTER
//=================================================================================================================

//=================================================================================================================
//                  ESTE CÓDIGO FOI SUBSTITUIDO PELA ANOTAÇÃO @EnableGlobalMethodSecurity (ESTÁ NO INICIO DESTA CLASSE)
//                 E PELAS ANOTAÇÕES @PreAuthorize (ESTÁ NA CLASSE StudentManagementController)
//
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
//=================================================================================================================

//=================================================================================================================
//               FORM LOGIN DESABILITADO PARA USAR O JWT AUTHENTICATION
//=================================================================================================================
//                .and()
//                .formLogin().permitAll()
//                .defaultSuccessUrl("/courses", true);
//=================================================================================================================

//=================================================================================================================
//      BASIC AUTH UTILIZADO NA PRIMEIRA PARTE DO CURSO ANTES DO FORM LOGIN
//=================================================================================================================
//               .httpBasic();  // Basic Auth: tem que fornecer login e senha para qualquer request
//=================================================================================================================


    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }


}

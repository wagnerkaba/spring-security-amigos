package com.wagner.springsecurityamigos.security;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.wagner.springsecurityamigos.security.ApplicationUserPermission.COURSE_WRITE;
import static com.wagner.springsecurityamigos.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor(onConstructor=@__(@Autowired))
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
//               SE DEIXAR CSRF HABILITADO, O SPRING GERA UM TOKEN CSRF QUE É GRAVADO EM UM COOKIE
//               E QUE TEM QUE SER RETORNADO EM QUALQUER REQUEST
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())

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


                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }


    // utilizado para pegar usuários do database
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails anaUser = User.builder()
                .username("ana")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();
        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();
        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password"))
//                .roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                anaUser, lindaUser, tomUser
        );

    }
}

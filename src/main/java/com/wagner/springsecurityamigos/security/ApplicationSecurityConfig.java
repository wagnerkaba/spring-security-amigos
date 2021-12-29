package com.wagner.springsecurityamigos.security;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.wagner.springsecurityamigos.security.ApplicationUserRole.ADMIN;
import static com.wagner.springsecurityamigos.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor(onConstructor=@__(@Autowired))
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }


    // utilizado para pegar usuários do database
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name()) //ROLE_STUDENT
                .build();
        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password"))
                .roles(ADMIN.name()) //ROLE_ADMIN
                .build();


        return new InMemoryUserDetailsManager(
                annaSmithUser, lindaUser
        );

    }
}

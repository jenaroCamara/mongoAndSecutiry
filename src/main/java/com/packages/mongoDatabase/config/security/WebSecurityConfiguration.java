package com.packages.mongoDatabase.config.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("usuario").roles("USUARIO").password("{noop}usuario")
                .and()
                .withUser("admin").roles("ADMIN", "USUARIO").password("{noop}admin");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST,"/persona").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,"/persona").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET,"/persona").permitAll()
                .antMatchers(HttpMethod.DELETE,"/persona/*").hasRole("ADMIN")
                .anyRequest().authenticated();
    }
}
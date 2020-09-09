package com.bbende.saml.config;

import com.bbende.saml.security.SimpleAuthenticationFilter;
import com.bbende.saml.security.SimpleAuthenticationProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${security.authentication.cookie.name}")
    private String authenticationCookieName;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(new SimpleAuthenticationProvider());
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        // allow access to SAML end-points to perform login sequence, everything else requires authentication
        http
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers("/").permitAll()
                    .antMatchers("/api/access/saml/**").permitAll()
                    .anyRequest().authenticated()
                .and()
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // add our simple authentication filter
        http.addFilterBefore(
                new SimpleAuthenticationFilter(authenticationCookieName),
                AnonymousAuthenticationFilter.class);
    }

}
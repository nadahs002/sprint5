package com.nada.employes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .cors().configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest
                                                                          request) {
                        CorsConfiguration config = new CorsConfiguration();

                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        config.setExposedHeaders(Arrays.asList("Authorization"));
                        config.setMaxAge(3600L);
                        return config;
                    }
                }).and()
                .authorizeRequests()
                // Consulter tous les produits
                .antMatchers("/api/all/**").hasAnyAuthority("ADMIN", "USER")
                // Consulter un produit par son id
                .antMatchers(HttpMethod.GET, "/api/getbyid/**").hasAnyAuthority("ADMIN", "USER")
                // Ajouter un nouveau produit
                .antMatchers(HttpMethod.POST, "/api/addprod/**").hasAnyAuthority("ADMIN")
                // Modifier un produit
                .antMatchers(HttpMethod.PUT, "/api/updateprod/**").hasAuthority("ADMIN")
                // Supprimer un produit
                .antMatchers(HttpMethod.DELETE, "/api/delprod/**").hasAuthority("ADMIN")
                .anyRequest().authenticated().and()
                .addFilterBefore(new JWTAuthorizationFilter(), BasicAuthenticationFilter.class);
        return http.build();
    }
}

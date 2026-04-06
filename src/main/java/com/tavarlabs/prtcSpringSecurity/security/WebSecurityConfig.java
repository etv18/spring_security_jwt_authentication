package com.tavarlabs.prtcSpringSecurity.security;

import com.tavarlabs.prtcSpringSecurity.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class WebSecurityConfig {

    /*
     * - PURPOSE -
     * This class is the blueprint which tells Spring how I want to set up my security config
     * and how he'll use the classes I defined earlier.
     *
     * - ABOUT BEANS -
     * As well here I defined the beans I want them to in the application context, so if I want to use
     * them in other packages the Spring IoC container can inject them properly. As an example of this we
     * have the AuthenticationManager bean, even though I'm not using it inside WebSecurityConfig
     * class I use it in AuthenticationController.
     ** */

    @Autowired
    CustomUserDetailsService userDetailsService;
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .exceptionHandling(e ->
                        e.authenticationEntryPoint(unauthorizedHandler)
                        /* Here I pass to Spring the object which will handle the response when
                        * a request is not valid.
                        **  */
                )
                .sessionManagement( s ->
                        s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                        /* Since we are implementing a REST api we use this Session Creation Policy
                        *  of STATELESS. Due to we are not going to use cookies or sessions for the
                        *  clients who interact with the api.
                        ** */
                )
                .authorizeHttpRequests( a ->
                    a.requestMatchers(
                            "/api/v1/auth/**",
                            "/api/v1/welcome"
                    ).permitAll().anyRequest().authenticated()

                );
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        /* This is one of the most important lines due to over here, we are telling Spring Security to use
        *  our authenticationJwtTokenFilter before UsernamePasswordAuthenticationFilter. What for?
        *
        *  Because we are using JWT authentication, and we are looking forward to authenticate the user now,
        *  before Spring tries to look for a traditional session or login form.
        ** */

        return http.build();
    }
}

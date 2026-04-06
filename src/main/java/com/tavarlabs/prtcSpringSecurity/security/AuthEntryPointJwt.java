package com.tavarlabs.prtcSpringSecurity.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    /*
    * This class implements this interface called 'AuthenticationEntryPoint', which is used
    * by Spring Security to set up a response you can send back to client.
    *
    * This method commence() is called by Spring Security when unauthenticated request hit a
    * secured endpoint, so it lets you define the response you wanna send back to the client
    * when this happens.
    *
    * Without this class Spring Security might just send a generic 403 forbidden or a "Whitelabel
    * Error Page".
    *
    * Parameters:
    *   - HttpServletRequest request: Gives you info about where the user was trying to go (the URI).
    *   - HttpServletResponse response: This object is the one which lets you set up a response you
    *       can send back to the client.
    *   - AuthenticationException authException: This contains the cause, it lets you know why the client
    *       failed. If "Bad Credentials", "Full authentication is required", etc...
    *
    * */

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException, ServletException {
       // System.out.println("PATH: " + request.getRequestURI() + "\nError in depth: " + authException.getMessage());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "401 Unauthorized you piece of shit");
    }
}

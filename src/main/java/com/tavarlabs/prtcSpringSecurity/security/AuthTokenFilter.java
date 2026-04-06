package com.tavarlabs.prtcSpringSecurity.security;

import com.tavarlabs.prtcSpringSecurity.service.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
public class AuthTokenFilter extends OncePerRequestFilter {

    /*
    * This class extends from OncePerRequestFilter because this class ensures our JWT validation
    * logic runs just once per incoming request. Once we verify the token, and we set it in the
    * Security Context Holder, all subsequent filters and controllers will recognize the user as
    * authenticated without needing to revalidate the token.
    *
    * This is efficient because instead of verifying the token in all the filters we just set it
    * in the Security Context Holder, so other filters can focus just on get information about the
    * user who owns the verified token.
    *
    * So basically it lets spring know it can treat the request as valid until
    * the end of its way.
    ** */

    public static final String BEARER_ = "Bearer ";

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = parseJwt(request);

        try {
            if (jwt != null && jwtUtil.validateJwtToken(jwt)){

                final String username = jwtUtil.getUserFromToken(jwt);
                final UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        } catch (Exception e) {
            log.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response); /* needed for the next filter chain, without this the client request
            won't reach other filters therefore it'll never reach the controller.
         **/
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (headerAuth != null && headerAuth.startsWith(BEARER_)) {
            return headerAuth.substring(BEARER_.length());
        }
        return null;
    }
}

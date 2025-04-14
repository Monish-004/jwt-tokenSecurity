package com.example.Spring.security.filter;

import com.example.Spring.security.serviceImplementation.JwtService;
import com.example.Spring.security.serviceImplementation.MyApplicationServiceLayer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter
{

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
    {
        // While validating this token, server will recieve the below thing.
        // Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJtb25pc2giLCJpYXQiOjE3NDQ1NDE4MzEsImV4cCI6MTc0NDU0MjAxMX0.T_rlweM2AErmc58hmRzu1zOPfp_2WcwIEr1SmHTFzhE
        // Now we need to say, skip the Bearer and space valdiate the token
        // this token is Request and token available in Header, so we can take this from HttpServletrequest object


        String authHeader = request.getHeader( "Authorization"); // Basically we have lot of things in header, so just we are fetching Authorization type of header.
        String token = null;
        String username = null;

        // It says authHeader should not be null and it starts with Bearer and Space, then go inside of the block
        if(authHeader != null && authHeader.startsWith("Bearer "))
        {
            token = authHeader.substring(7); // It saying skip the Bearer and space and start with token and that token is assigned to variable token, Now null is replaced.
            username = jwtService.extractUserName(token); // From the token, we decoded username alone, Basically the token will be encoded format.
        }

        // Now we got correct token and username, we need to validate now.
        // It says username should not be null and the next one need to be null, if it is not null it is already authenticated.
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null)
        {
            // we need to interact with DB and find the username.
            // many other ways are there, but this way does not contain empty object.
            UserDetails userDetails = context.getBean(MyApplicationServiceLayer.class).loadUserByUsername(username);

            // if the token is valid , we need to give this to another filter and that filter is UsernamePasswordAuthenticationFilter.
            if(jwtService.validateToken(token, userDetails))
            {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                // Now the authToken only knows about user, but it does not have idea about request object.
                // request object contains lot of data, so authToken should know that also.
                //authToken.setDetails(new webAu);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails (request));

                // previously it was not authenticated, so it entering to block
                // Now, we are setting to authenticated
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        // It says, once the filter is completed move to next filter.
        // Filter work is done, JwtFilter validates a token and creates a authentication object and pass it to next.
        filterChain.doFilter(request,response);
    }

}

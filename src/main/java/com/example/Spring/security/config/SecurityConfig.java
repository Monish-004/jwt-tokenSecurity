package com.example.Spring.security.config;

import com.example.Spring.security.entity.MyApplication;
import com.example.Spring.security.filter.JwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Configuration
@EnableWebSecurity
public class SecurityConfig
{

    @Autowired
    @Lazy
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    // DB CONFIGURATION
    @Bean
    public AuthenticationProvider authProvider()
    {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(); // We are Connecting DB with DAO Layer.
        provider.setUserDetailsService (userDetailsService); // Authentication Provider wants to work,
        // then it will ask for Service Class, Now this service(userDetailsService) is a interface.
        // So we need a implementation, so we implemented in {MyUserDetailsService} our ServiceImplementation.
        provider.setPasswordEncoder(new BCryptPasswordEncoder());  // Authenticate, Cross verifies
        // the password, which is stored in DB as a Secret Key [ Hashed Text ]
        // provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance()); // Authenticate, Cross verifies
        // the password, which is stored in DB as a plain text.
        return provider;
    }

    // SECURITY CONFIGURATION
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception
    {
         httpSecurity.authorizeHttpRequests(authenticate -> authenticate.requestMatchers("/register","login").permitAll()); // FOR JWT, so "login" is here
        // httpSecurity.authorizeHttpRequests(authenticate -> authenticate.requestMatchers("/register").permitAll()); // For Spring Security no "login" URL needed it is default inbuilt method.
        httpSecurity.csrf(cust -> cust.disable());
        httpSecurity.authorizeHttpRequests(request -> request.anyRequest().authenticated());
        //httpSecurity.formLogin(Customizer.withDefaults());
        httpSecurity.httpBasic(Customizer.withDefaults());
        httpSecurity.sessionManagement (session -> session.sessionCreationPolicy (SessionCreationPolicy. STATELESS));
        httpSecurity.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception
    {
        return configuration.getAuthenticationManager();
    }
}

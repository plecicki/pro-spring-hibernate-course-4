package com.kodilla.library.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("user").roles("USER");
        auth.inMemoryAuthentication().withUser("librarian").password("librarian").roles("LIBRARIAN");

        //EXERCISE 4.4
        auth.inMemoryAuthentication().withUser("basic").password("basic").roles("BASIC");
        auth.inMemoryAuthentication().withUser("advanced").password("advanced").roles("ADVANCED");
        auth.inMemoryAuthentication().withUser("admin").password("admin").roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();

        http.authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/books/**")
                .hasAnyRole("USER", "LIBRARIAN", "ADMIN")
                .mvcMatchers(HttpMethod.POST, "/**")
                .hasAnyRole("LIBRARIAN", "ADMIN")
                .mvcMatchers(HttpMethod.DELETE, "/**")
                .hasAnyRole("ADMIN")

                //EXERCISE 4.4 - lack of module 3.3 because it doesn't exist
                .mvcMatchers(HttpMethod.GET, "/convert/**")
                .hasAnyRole("BASIC", "ADVANCED", "ADMIN")
                .mvcMatchers(HttpMethod.GET, "/v1/bean/**")
                .hasAnyRole("BASIC", "ADVANCED", "ADMIN")
                .mvcMatchers(HttpMethod.GET, "/v1/calculator/**")
                .hasAnyRole("BASIC", "ADVANCED", "ADMIN")
                .mvcMatchers(HttpMethod.GET, "/integration/**")
                .hasAnyRole("BASIC", "ADVANCED", "ADMIN")

                .mvcMatchers(HttpMethod.GET, "/integration/strings", "/integration/books")
                .hasAnyRole("ADVANCED", "ADMIN")
                .mvcMatchers(HttpMethod.POST, "/custom/**")
                .hasAnyRole("ADVANCED", "ADMIN")

                .mvcMatchers(HttpMethod.GET, "/v1/academy/**")
                .hasAnyRole("ADMIN")
                .mvcMatchers(HttpMethod.GET, "/orders/**")
                .hasAnyRole("ADMIN")
                .mvcMatchers(HttpMethod.POST, "/integration/**")
                .hasAnyRole("ADMIN")

                .anyRequest()
                .fullyAuthenticated()
                .and()
                .httpBasic();
    }
}

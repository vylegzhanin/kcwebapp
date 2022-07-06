package kcwebapp

import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.config.ConfigurableBeanFactory
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Scope
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.session.SessionRegistryImpl
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy
import org.springframework.security.web.session.HttpSessionEventPublisher
import org.springframework.security.web.session.SessionManagementFilter

import javax.servlet.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfiguration extends KeycloakWebSecurityConfigurerAdapter {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakAuthenticationProvider())
    }

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl())
    }

    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> getHttpSessionEventPublisher() {
        new ServletListenerRegistrationBean<HttpSessionEventPublisher>(new HttpSessionEventPublisher())
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure http
        http
                .headers().frameOptions().sameOrigin().disable()
                .addFilterBefore(corsFilter(), SessionManagementFilter.class)
                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                .and()
                .authorizeRequests()
                .antMatchers("/assets/*").permitAll()
                .antMatchers("/auth/*").permitAll()
                .antMatchers("/error/*").permitAll()
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().hasAnyAuthority("RoleUser")
    }


    Filter corsFilter() {
        return new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                                 FilterChain filterChain) throws IOException, ServletException {

                HttpServletResponse response = (HttpServletResponse) servletResponse
                HttpServletRequest request = (HttpServletRequest) servletRequest

                response.setHeader("Access-Control-Allow-Origin", request.getHeader("Origin"))
                response.setHeader("Access-Control-Allow-Methods", request.getHeader("Access-Control-Request-Method"))
                response.setHeader("Access-Control-Allow-Headers", request.getHeader("Access-Control-Request-Headers"))
                response.setHeader("Access-Control-Allow-Credentials", "true")
                response.setHeader("Access-Control-Max-Age", "180")

                filterChain.doFilter(servletRequest, servletResponse)
            }

            @Override
            public void init(FilterConfig filterConfig) throws ServletException {

            }

            @Override
            public void destroy() {
            }
        }
    }

    @Autowired
    public KeycloakClientRequestFactory keycloakClientRequestFactory

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate keycloakRestTemplate() {
        return new KeycloakRestTemplate(keycloakClientRequestFactory)
    }
}
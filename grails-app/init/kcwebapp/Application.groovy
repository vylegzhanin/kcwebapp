package kcwebapp

import grails.boot.GrailsApp
import grails.boot.config.GrailsAutoConfiguration
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents
import org.springframework.context.annotation.ComponentScan

@ComponentScan(basePackageClasses = [KeycloakSecurityComponents.class, SecurityConfiguration.class])
class Application extends GrailsAutoConfiguration {
    static void main(String[] args) {
        GrailsApp.run(Application, args)
    }
}
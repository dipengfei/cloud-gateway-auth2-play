package me.danielpf.cloudgatewayauth2play.gatewayserver;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@SpringBootApplication
@EnableWebFluxSecurity
@Slf4j
public class GatewayServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayServerApplication.class, args);
    }


    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                      .route("oauth", r -> r.path("/oauth/**")
                                            .uri("http://localhost:8081"))
                      .route("resource", r -> r.path("/resource/**").filters(f -> f.filter(
                              (exchange, chain) -> exchange.getPrincipal()
                                                           .doOnNext(principal -> {
                                                               JwtAuthenticationToken token = (JwtAuthenticationToken) principal;
                                                               log.info("current client id: {}", token.getToken()
                                                                                                      .getClaims()
                                                                                                      .get("client_id"));
                                                           })
                                                           .then(chain.filter(exchange))))
                                               .uri("http://localhost:8085"))
                      .build();
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http.csrf().disable()
            .authorizeExchange().pathMatchers("/oauth/**").permitAll()
            .anyExchange().authenticated()
            .and()
            .oauth2ResourceServer()
            .jwt();
        return http.build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {

        Resource resource = new ClassPathResource("public.txt");
        String content;
        try {
            content = IOUtils.toString(resource.getInputStream());
            String publicKeyContent = content.replaceAll("\\n", "")
                                             .replace("-----BEGIN PUBLIC KEY-----", "")
                                             .replace("-----END PUBLIC KEY-----", "");

            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
            RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(keySpecX509);

            return new NimbusReactiveJwtDecoder(publicKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    @Bean
    public MapReactiveUserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("dummy").roles("USER").build();
        return new MapReactiveUserDetailsService(user);
    }
}

package me.danielpf.cloudgatewayauth2play.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootApplication
public class ResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerApplication.class, args);
    }

    @Bean
    public RouterFunction<ServerResponse> routingFunction() {
        return RouterFunctions.route(RequestPredicates.path("/resource"),
                                     req -> {
                                         Map<String, Object> data = new LinkedHashMap<>();
                                         data.put("path", req.path());
                                         try {
                                             InetAddress addr = InetAddress.getLocalHost();
                                             data.put("serverAddress", addr.getHostAddress());
                                         } catch (UnknownHostException e) {
                                             e.printStackTrace();
                                         }
                                         return ServerResponse.ok().body(BodyInserters.fromObject(data));
                                     });
    }

}

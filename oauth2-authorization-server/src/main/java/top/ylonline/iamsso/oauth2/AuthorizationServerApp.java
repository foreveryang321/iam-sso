package top.ylonline.iamsso.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * @author yl
 */
@SpringBootApplication
public class AuthorizationServerApp extends SpringBootServletInitializer {
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(AuthorizationServerApp.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApp.class, args);
    }
}

package top.ylonline.iamsso.user;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 * @author yl
 */
@SpringBootApplication
public class ResourceServerApp extends SpringBootServletInitializer {
    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(ResourceServerApp.class);
    }

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerApp.class, args);
    }
}

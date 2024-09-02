package org.zerock.api01.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;
//import springfox.documentation.builders.ApiInfoBuilder;
//import springfox.documentation.builders.PathSelectors;
//import springfox.documentation.builders.RequestHandlerSelectors;
//import springfox.documentation.service.ApiInfo;
//import springfox.documentation.spi.DocumentationType;
//import springfox.documentation.spring.web.plugins.Docket;

@Configuration
public class SwaggerConfig {
/*
    @Bean
    public OpenAPI api() {
        String key = "Access Token (Bearer)";
        String refreshKey = "Refresh Token";

        SecurityRequirement securityRequirement = new SecurityRequirement().addList("Authorization");

        SecurityScheme accessTokenSecurityScheme = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP);

        SecurityScheme refrestTokenSecurityScheme = new SecurityScheme()
                .type(SecurityScheme.Type.APIKEY);

        SecurityScheme aSecurityScheme = new SecurityScheme()
                .name("Authorization")
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                ;

        Components components = new Components()
                .addSecuritySchemes(key, accessTokenSecurityScheme)
                .addSecuritySchemes(refreshKey, refrestTokenSecurityScheme);

        Components components1 = new Components()
                .addSecuritySchemes("Authorization", aSecurityScheme)
                .addSecuritySchemes(refreshKey, refrestTokenSecurityScheme);

        return new OpenAPI()
                .info(new Info().title("title").description("description").version("version"))
                .addSecurityItem(securityRequirement)
                //.components(components)
                .components(new Components().addSecuritySchemes("Authorization",
                        new SecurityScheme()
                                .name("Authorization")
                                //.type(SecurityScheme.Type.HTTP)
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                        )
                );



    }
 */
/*
        return new Docket(DocumentationType.OAS_30)
                .useDefaultResponseMessages(false)
                .select()
                .apis(RequestHandlerSelectors.withClassAnnotation(RestController.class))
                .paths(PathSelectors.any())
                .build()
                .apiInfo(apiInfo());

              private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("BOOT Api 01 Project Swagger")
                .build();
    }
 */
}

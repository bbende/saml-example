package com.bbende.saml;

import com.bbende.saml.config.SamlProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(SamlProperties.class)
public class SamlExampleApplication {

	public static void main(String[] args) {
		SpringApplication.run(SamlExampleApplication.class, args);
	}

}

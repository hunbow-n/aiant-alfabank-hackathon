package ru.alfagen.pdsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class PdSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(PdSecurityApplication.class, args);
    }
}
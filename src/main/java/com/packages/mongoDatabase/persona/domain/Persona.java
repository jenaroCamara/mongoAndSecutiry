package com.packages.mongoDatabase.persona.domain;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import javax.annotation.processing.Generated;
import java.util.Date;

@Data
@Document
public class Persona {
    @Id //usar generador de codigo automatico
    String id;
    String usuario;
    String name;
    String password;
    String surname;
    String company_email;
    String personal_email;
    String city;
    boolean active;
    Date created_date;
    String imagen_url;
    Date termination_date;
}

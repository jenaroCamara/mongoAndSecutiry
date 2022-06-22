package com.packages.mongoDatabase.persona.infraestructure.dtopersona;

import lombok.Data;

import java.util.Date;

@Data
public class PersonaDTOoutput {
    String usuario;
    String name;
    String surname;
    String company_email;
    String personal_email;
    String city;
    boolean active;
    Date created_date;
    String imagen_url;
    Date termination_date;
}

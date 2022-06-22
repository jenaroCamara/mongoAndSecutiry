package com.packages.mongoDatabase.persona.application.Port;

import com.packages.mongoDatabase.persona.domain.Persona;
import com.packages.mongoDatabase.persona.infraestructure.dtopersona.PersonaDTOinput;
import com.packages.mongoDatabase.persona.infraestructure.dtopersona.PersonaDTOoutput;

import java.util.List;
import java.util.Map;

public interface PersonaServiceInterface {
    PersonaDTOoutput create(PersonaDTOinput persona);
    List<PersonaDTOoutput> read();
    PersonaDTOoutput update(PersonaDTOinput persona);
    Map<String, String> delete(String id);
}

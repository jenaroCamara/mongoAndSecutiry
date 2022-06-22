package com.packages.mongoDatabase.persona.infraestructure.controller;

import com.packages.mongoDatabase.persona.application.Port.PersonaServiceInterface;
import com.packages.mongoDatabase.persona.domain.Persona;
import com.packages.mongoDatabase.persona.infraestructure.dtopersona.PersonaDTOinput;
import com.packages.mongoDatabase.persona.infraestructure.dtopersona.PersonaDTOoutput;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("persona")
public class Controller {
    @Autowired
    private PersonaServiceInterface personaService;
    @Autowired
    private ModelMapper modelMapper;

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public PersonaDTOoutput guardarPersona(@RequestBody PersonaDTOinput persona) {

        return personaService.create(persona);
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public List<PersonaDTOoutput> getAllPeople() {
        return personaService.read();
    }

    @PutMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public PersonaDTOoutput actualizaPersona(@RequestBody PersonaDTOinput persona) {

        return personaService.update(persona);
    }

    @DeleteMapping("/{id}")
    public Map<String, String> deletePersona(@PathVariable String id) {
        return personaService.delete(id);
    }
}

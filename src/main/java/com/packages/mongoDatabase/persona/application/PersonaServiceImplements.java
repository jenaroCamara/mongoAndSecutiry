package com.packages.mongoDatabase.persona.application;

import com.packages.mongoDatabase.persona.application.Port.PersonaServiceInterface;
import com.packages.mongoDatabase.persona.domain.Persona;
import com.packages.mongoDatabase.persona.infraestructure.dtopersona.PersonaDTOinput;
import com.packages.mongoDatabase.persona.infraestructure.dtopersona.PersonaDTOoutput;
import com.packages.mongoDatabase.persona.infraestructure.repository.PersonaRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class PersonaServiceImplements implements PersonaServiceInterface {
    @Autowired
    PersonaRepository personaRepository;
    @Autowired
    private ModelMapper modelMapper;
    @Override
    public PersonaDTOoutput create(PersonaDTOinput persona){
        //personaRepository.findById(persona.getId()).orElseThrow(()->new RuntimeException("Fallo al crear"));
        Persona personaEntity = modelMapper.map(persona,Persona.class);
        return modelMapper.map(personaRepository.save(personaEntity),PersonaDTOoutput.class);
    }

    @Override
    public List<PersonaDTOoutput> read(){
        List<Persona> lista = personaRepository.findAll();
        List<PersonaDTOoutput> lista2 = lista.stream()
                .map(persona -> modelMapper.map(persona,PersonaDTOoutput.class))
                .collect(Collectors.toList());
        return lista2;
    }

    @Override
    public PersonaDTOoutput update(PersonaDTOinput persona){
        //personaRepository.findById(persona.getId()).orElseThrow(()->new RuntimeException("Fallo al actualizar"));
        return modelMapper.map(personaRepository.save(modelMapper.map(persona,Persona.class)),PersonaDTOoutput.class);
    }

    @Override
    public Map<String, String> delete(String id){
        //Persona p = personaRepository.findById(id).orElseThrow(()->new RuntimeException("Fallo al crear"));

        // cuenta antes de borrar
        long beforeDelete = personaRepository.count();
        // borrado
        personaRepository.deleteById(id);
        // Cuenta despues de borrar
        long afterDelete = personaRepository.count();

        String messageValue = beforeDelete == afterDelete ? "Algo no ha salido bien!" : "Persona eliminada";

        Map<String, String> deleteMap = new HashMap<>();
        deleteMap.put("message", messageValue);

        return deleteMap;
    }

}

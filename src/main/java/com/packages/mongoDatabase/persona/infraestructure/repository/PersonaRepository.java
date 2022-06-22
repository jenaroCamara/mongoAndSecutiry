package com.packages.mongoDatabase.persona.infraestructure.repository;

import com.packages.mongoDatabase.persona.domain.Persona;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PersonaRepository extends MongoRepository<Persona, String> {
}

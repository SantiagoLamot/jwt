package com.example.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.jwt.model.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario,Long>{
    Optional<Usuario> findByUsername(String username);
}



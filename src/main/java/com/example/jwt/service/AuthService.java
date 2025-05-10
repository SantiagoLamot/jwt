package com.example.jwt.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.jwt.dto.AuthRequest;
import com.example.jwt.dto.AuthResponse;
import com.example.jwt.model.Rol;
import com.example.jwt.model.Usuario;
import com.example.jwt.repository.UsuarioRepository;
import com.example.jwt.security.JwtService;

import lombok.RequiredArgsConstructor;
@Service
@RequiredArgsConstructor
public class AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtUtil;

    @Autowired 
    private UsuarioRepository usuarioRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AuthResponse login (AuthRequest request){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        UserDetails userDetails = usuarioRepository.findByUsername(request.getUsername()).orElseThrow();
        String token = jwtUtil.generarToken(userDetails);
        
        return new AuthResponse(token);
    }

    public AuthResponse register(AuthRequest request) {
        Usuario usuario = new Usuario();
        usuario.setUsername(request.getUsername());
        usuario.setPassword(passwordEncoder.encode(request.getPassword()));
        usuario.setRol(Rol.ADMINISTRADOR);
        usuarioRepository.save(usuario);
        return new AuthResponse(jwtUtil.generarToken(usuario));
    }
}

package me.sonam.auth.jpa.repo;

import me.sonam.auth.jpa.entity.TokenMediate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface TokenMediateRepository extends JpaRepository<TokenMediate, UUID> {
}

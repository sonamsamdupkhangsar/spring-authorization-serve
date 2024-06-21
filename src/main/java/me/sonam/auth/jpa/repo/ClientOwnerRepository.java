package me.sonam.auth.jpa.repo;

import me.sonam.auth.jpa.entity.ClientOwner;
import me.sonam.auth.jpa.entity.ClientUser;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ClientOwnerRepository extends JpaRepository<ClientOwner, UUID> {
    List<ClientOwner> findByUserId(UUID userId, Pageable pageable);
    long countByUserId(UUID userId);
}

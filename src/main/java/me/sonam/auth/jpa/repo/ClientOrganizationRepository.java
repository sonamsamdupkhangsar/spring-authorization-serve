package me.sonam.auth.jpa.repo;

import me.sonam.auth.jpa.entity.ClientOrganization;
import me.sonam.auth.jpa.entity.ClientOrganizationId;
import org.springframework.data.jpa.repository.JpaRepository;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;

public interface ClientOrganizationRepository extends JpaRepository<ClientOrganization, ClientOrganizationId> {
    Optional<ClientOrganization> findByClientId(String clientId);
    Optional<Boolean> existsByClientId(String clientId);
}

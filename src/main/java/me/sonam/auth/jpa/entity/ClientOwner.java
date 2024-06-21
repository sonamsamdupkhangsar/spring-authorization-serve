package me.sonam.auth.jpa.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "ClientOwner")
public class ClientOwner {
    @Id
    private UUID clientId;
    private UUID userId;

    public ClientOwner() {

    }

    public ClientOwner(UUID clientId, UUID userId) {
        this.clientId = clientId;
        this.userId = userId;
    }

    public UUID getClientId() {
        return this.clientId;
    }

    public UUID getUserId() {
        return this.userId;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;
        ClientOwner that = (ClientOwner) object;
        return Objects.equals(clientId, that.clientId) && Objects.equals(userId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, userId);
    }

    @Override
    public String toString() {
        return "ClientOwner{" +
                "clientId=" + clientId +
                ", userId=" + userId +
                '}';
    }
}

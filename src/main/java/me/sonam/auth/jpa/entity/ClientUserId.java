package me.sonam.auth.jpa.entity;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

public class ClientUserId implements Serializable {
    private String clientId;
    private UUID userId;

    public ClientUserId(String clientId, UUID userId) {
        this.clientId = clientId;
        this.userId = userId;
    }

    public ClientUserId() {}
    public String getClientId() {
        return clientId;
    }

    public UUID getUserId() {
        return userId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientUserId that = (ClientUserId) o;
        return Objects.equals(clientId, that.clientId) && Objects.equals(userId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, userId);
    }

    @Override
    public String toString() {
        return "ClientUserId{" +
                "clientId='" + clientId + '\'' +
                ", userId=" + userId +
                '}';
    }
}

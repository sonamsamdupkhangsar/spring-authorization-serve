package me.sonam.auth.jpa.entity;

import java.io.Serializable;
import java.util.Objects;
import java.util.UUID;

public class ClientOrganizationId implements Serializable {
    private UUID clientId;
    private UUID organizationId;

    public ClientOrganizationId(UUID clientId, UUID organizationId) {
        this.clientId = clientId;
        this.organizationId = organizationId;
    }

    public ClientOrganizationId() {}
    public UUID getClientId() {
        return clientId;
    }

    public UUID getOrganizationId() {
        return organizationId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientOrganizationId that = (ClientOrganizationId) o;
        return Objects.equals(clientId, that.clientId) && Objects.equals(organizationId, that.organizationId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, organizationId);
    }

    @Override
    public String toString() {
        return "ClientOrganizationId{" +
                "clientId='" + clientId + '\'' +
                ", organizationId=" + organizationId +
                '}';
    }
}

import java.time.LocalDateTime;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class User {

	private UUID id;

	private UUID uuid;

	private String username;

	private int userRank;

	private int donorRank;

	private LocalDateTime createdAt;

	private LocalDateTime updatedAt;

	public UUID getId() {
		return id;
	}

	public void setId(UUID id) {
		this.id = id;
	}

	public UUID getUuid() {
		return uuid;
	}

	public void setUuid(UUID uuid) {
		this.uuid = uuid;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public int getUserRank() {
		return userRank;
	}

	public void setUserRank(int userRank) {
		this.userRank = userRank;
	}

	public int getDonorRank() {
		return donorRank;
	}

	public void setDonorRank(int donorRank) {
		this.donorRank = donorRank;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}

	public LocalDateTime getUpdatedAt() {
		return updatedAt;
	}

	public void setUpdatedAt(LocalDateTime updatedAt) {
		this.updatedAt = updatedAt;
	}

	@Deprecated
	public int getDrank() {
		return getDonorRank();
	}

	@Deprecated
	public int getUrank() {
		return getUserRank();
	}

	@Override
	public String toString() {
		return "User [id=" + id + ", uuid=" + uuid + ", username=" + username + ", userRank=" + userRank
				+ ", donorRank=" + donorRank + ", createdAt=" + createdAt + ", updatedAt=" + updatedAt + "]";
	}
}
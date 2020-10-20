import java.util.List;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class UserRepo {

	private static Client client = ClientBuilder.newClient();

	public static User update(User user) {
		User updatedUser = client
				.target("http://127.0.0.1:8080/user")
				.request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(user, MediaType.APPLICATION_JSON), Response.class)
				.readEntity(new GenericType<User>() {});
		return updatedUser;
	}

	public static List<User> getAllUsers(){
		List<User> allUsers = client
				.target("http://127.0.0.1:8080/user/all")
				.request(MediaType.APPLICATION_JSON)
				.get(Response.class)
				.readEntity(new GenericType<List<User>>() {});
		return allUsers;
	}

	public static User getUser(UUID uuid) {
		User userByUuid = client
				.target("http://127.0.0.1:8080/user/uuid")
				.queryParam("uuid", uuid)
				.request(MediaType.APPLICATION_JSON)
				.get(Response.class)
				.readEntity(new GenericType<User>() {});
		return userByUuid;
	}

	public static User getUser(String username) {
		User userByName = client
				.target("http://127.0.0.1:8080/user/name")
				.queryParam("name", username)
				.request(MediaType.APPLICATION_JSON)
				.get(Response.class)
				.readEntity(new GenericType<User>() {});
		return userByName;
	}
}
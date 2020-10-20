import java.util.List;
import java.util.UUID;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


public class PluginApp {

	public static void main(String[] args) throws Exception {

		Client client = ClientBuilder.newClient();

		User user = new User();
		user.setUuid(UUID.randomUUID());
		user.setDonorRank(0);
		user.setUserRank(10);
		user.setUsername("HydroTekZ");

		User createdUser = client
				.target("http://127.0.0.1:8080/user")
				.request(MediaType.APPLICATION_JSON)
				.post(Entity.entity(user, MediaType.APPLICATION_JSON), Response.class)
				.readEntity(new GenericType<User>() {});
		System.out.println("NEW USER -> " + createdUser);

		List<User> allUsers = client
				.target("http://127.0.0.1:8080/user/all")
				.request(MediaType.APPLICATION_JSON)
				.get(Response.class)
				.readEntity(new GenericType<List<User>>() {});
		System.out.println("ALL USERS -> " + allUsers.toString());

		User userByUuid = client
				.target("http://127.0.0.1:8080/user/uuid")
				.queryParam("uuid", user.getUuid())
				.request(MediaType.APPLICATION_JSON)
				.get(Response.class)
				.readEntity(new GenericType<User>() {});
		System.out.println("BY UUID -> " + userByUuid.toString());

		User userByName = client
				.target("http://127.0.0.1:8080/user/name")
				.queryParam("name", user.getUsername())
				.request(MediaType.APPLICATION_JSON)
				.get(Response.class)
				.readEntity(new GenericType<User>() {});
		System.out.println("BY NAME -> " + userByName.toString());


	}

}
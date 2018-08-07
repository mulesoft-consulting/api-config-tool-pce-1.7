package com.mulesoft.java;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Vector;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.MultiPartFeature;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.CollectionType;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;

public class ApiConfigTool {
	public static String anypoint_platform_platform_base_uri="anypoint_platform_platform_base_uri";
	public static String HTTPS_ANYPOINT_MULESOFT_COM = System.getenv(anypoint_platform_platform_base_uri);
	public static Boolean VALIDATE_AP_SERVER_CERT = false;
	public static boolean makeApiNameBusinessGroupSensitive = false;
	public static String RESOURCES_DIR = "src/main/resources";
	public static String API_VERSION_HEADER_MSG = "ApiConfigTool(v.PCE-1.7) version 2.0.0";

	public static void main(String[] args) {

		try {
			if (args.length <= 6) {
				System.err.println(API_VERSION_HEADER_MSG);
				System.err.println("\n");
				printHelp();
			} else if (HTTPS_ANYPOINT_MULESOFT_COM == null || HTTPS_ANYPOINT_MULESOFT_COM.isEmpty()) {
				System.err.println("Set the system environment variable " + anypoint_platform_platform_base_uri + " before running");
			} else if (args[0].equals("configureProjectResourceFile")) {
				System.err.println(API_VERSION_HEADER_MSG + " connecting to " + HTTPS_ANYPOINT_MULESOFT_COM + ", starting "
			         + args[0] + " environment: " + args[6]);
				LinkedHashMap<String, Object> returnMap = configureApi((args.length > 1) ? args[1] : "userName",
						(args.length > 2) ? args[2] : "userPass", 
						(args.length > 3) ? args[3] : "orgName",
						(args.length > 4) ? args[4] : "apiName", 
						(args.length > 5) ? args[5] : "apiVersion",
						(args.length > 6) ? args[6] : "DEV", 
						(args.length > 7) ? args[7] : "client-credentials-policy",
						(args.length > 8) ? args[8] : "empty-client-access-list");
				updateProjectResourceConfigProperties(returnMap);
				System.err.println(API_VERSION_HEADER_MSG + " Successful completion " + args[0] + " environment: " + args[6]);
				System.err.println("\n");
			} else {
				printHelp();
			}
		} catch (Exception e) {
			e.printStackTrace(System.err);
			System.exit(500);
		}
	}
	
	private static void updateProjectResourceConfigProperties(LinkedHashMap<String, Object> map) {
		Properties configProperties = new SortedProperties();
		FileInputStream input = null;
		FileOutputStream output = null;
		File resourcesDir = new File(RESOURCES_DIR);

/*
		ObjectMapper mapperw = new ObjectMapper();
		String result;
		try {
			result = mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(map);
			System.out.println(result);
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}		
*/
		try {
			StringBuilder filename = new StringBuilder();
			filename.append(map.get("envName")).append("-config.properties");
			File file = new File(resourcesDir, filename.toString());
			if (file.exists()) {
				input = FileUtils.openInputStream(file);

				// load a properties file
				configProperties.load(input);
				/*
				 * System.out.println(configProperties.getProperty("api.name"));
				 * System.out.println(configProperties.getProperty("api.version"));
				 * System.out.println(configProperties.getProperty("api.id"));
				 */

				LinkedHashMap<String, String> generatedProperties = (LinkedHashMap<String, String>) map
						.get("properties");
				configProperties.put("api.name", generatedProperties.get("auto-discovery-apiName"));
				configProperties.put("api.version", generatedProperties.get("auto-discovery-apiVersion"));
				configProperties.put("api.id", generatedProperties.get("auto-discovery-apiId"));

				output = FileUtils.openOutputStream(file);
				configProperties.store(output, null);
			} else {
				System.err.println("***WARN*** " + file.getAbsolutePath() + " does not exist.");
			}
		} catch (IOException ex) {
			IOUtils.closeQuietly(input);
			IOUtils.closeQuietly(output);
			ex.printStackTrace();
			System.exit(2);
		} finally {
			IOUtils.closeQuietly(input);
			IOUtils.closeQuietly(output);
		}
	}

	private static void printHelp() {
		System.out.println("\nUsage: java -jar ApiConfigTool {operation} [parameters]\n");
		System.out.println("  operations:");
		System.out.println("    configureProjectResourceFile   -Read the Api definition and publish it to Anypoint Platform,");
		System.out.println("                                    updating src/main/resources/<env>-config.properties");
		System.out.println("      Parameters:");
		System.out.println("          userName      -Anypoint user name required");
		System.out.println("          userPassword  -Anypoint user's password required");
		System.out.println("          orgName       -Anypoint business org name (no hierarchy) required");
		System.out.println("          apiName       -api name required");
		System.out.println("          apiVersion    -api version required");
		System.out.println("          env           -environment name required");
		System.out.println("          policies      -file containing policy definitions (json array) optional");
		System.out.println("          applications  -file containing client application namess to register for access (json array) optional");
		System.out.println("\n");
	}

	@SuppressWarnings("unchecked")
	private static LinkedHashMap<String, Object> configureApi(String userName, String userPass, String businessGroupName, String apiName,
			String apiVersion, String environmentName, String policies, String clients) throws Exception {
		
		HostnameVerifier allHostsValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};

		TrustManager[] trustManager = new X509TrustManager[] { new X509TrustManager() {

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkClientTrusted(X509Certificate[] certs, String authType) {

			}

			@Override
			public void checkServerTrusted(X509Certificate[] certs, String authType) {

			}
		} };

		LinkedHashMap<String, Object> returnPayload = new LinkedHashMap<String, Object>();
		LinkedHashMap<String, String> returnPayloadProperties = new LinkedHashMap<String, String>();

		SSLContext sslContext = SSLContext.getInstance("SSL");
		sslContext.init(null, trustManager, null);
		
		Client client = null;
		if (VALIDATE_AP_SERVER_CERT) {
			client = ClientBuilder.newClient();
		} else {
			client = ClientBuilder.newBuilder().sslContext(sslContext).hostnameVerifier(allHostsValid).build();
		}		
		client.register(JacksonJsonProvider.class).register(MultiPartFeature.class);

		returnPayload.put("projectName", "auto-api-registation");
		returnPayload.put("branchName", apiName);
		returnPayload.put("instanceId", apiVersion);
		returnPayload.put("envName", environmentName);

		// registration steps

		/*
		 * Authenticate with Anypoint Platform
		 */
		String apToken = getAPToken(client, userName, userPass);
		String authorizationHdr = "Bearer " + apToken;

		/*
		 * Get the login user information, organizationId and business group id
		 */
		LinkedHashMap<String, Object> myInformation = getMyInformation(client, authorizationHdr);
		String myOrganizationId = (String) ((LinkedHashMap<String, Object>) myInformation.get("user"))
				.get("organizationId");
		String myOrganizationName = (String) ((LinkedHashMap<String, Object>) ((LinkedHashMap<String, Object>) myInformation
				.get("user")).get("organization")).get("name");

		ArrayList<LinkedHashMap<String, Object>> memberOfOrganizations = (ArrayList<LinkedHashMap<String, Object>>) ((LinkedHashMap<String, Object>) myInformation
				.get("user")).get("memberOfOrganizations");
		LinkedHashMap<String, Object> businessGroupInformation = getBusinessGroupInformation(memberOfOrganizations,
				businessGroupName);
		String businessGroupId = (String) businessGroupInformation.get("id");

		/*
		 * Get the environment id
		 */
		LinkedHashMap<String, Object> environment = getEnvironmentInformation(client, authorizationHdr, businessGroupId,
				environmentName);
		String environmentId = (String) environment.get("id");
		ArrayList<LinkedHashMap<String, Object>> applications = null;
		LinkedHashMap<String, Object> applicationInfo = null;

		/*
		 * Create default CPS credential if it doesn't already exist
		 */
/*
		String cps_client_name = null;
		String cps_client_id = null;
		String cps_client_secret = null;
		StringBuilder cpsName = new StringBuilder();
		cpsName.append("configuration-property-service").append("_").append(businessGroupName).append("_")
				.append(environmentName);
		createApplication(client, authorizationHdr, myOrganizationId, cpsName.toString(),
				"Use for interacting with configuration property service");
		applications = getApplicationList(client, authorizationHdr, myOrganizationId);
		for (LinkedHashMap<String, Object> e:applications) {
			if (e.get("name").equals(cpsName.toString())) {
				applicationInfo = getApplicationInformation(client, authorizationHdr, myOrganizationId, (int) e.get("id"));
				cps_client_name = (String) applicationInfo.get("name");
				cps_client_id = (String) applicationInfo.get("clientId");
				cps_client_secret = (String) applicationInfo.get("clientSecret");
				break;
			}
		}
*/
		
		/*
		 * Create auto-registration credential if it doesn't already exist
		 */
/*
		String auto_reg_client_name = null;
		String auto_reg_client_id = null;
		String auto_reg_client_secret = null;
		StringBuilder autoRegistrationName = new StringBuilder();
		autoRegistrationName.append("auto-api-registration").append("_").append(businessGroupName).append("_")
				.append(environmentName);
		createApplication(client, authorizationHdr, myOrganizationId, autoRegistrationName.toString(),
				"Use for interacting with Auto Registration");
		applications = getApplicationList(client, authorizationHdr, myOrganizationId);
		applicationInfo = null;
		for (LinkedHashMap<String, Object> e:applications) {
			if (e.get("name").equals(autoRegistrationName.toString())) {
				applicationInfo = getApplicationInformation(client, authorizationHdr, myOrganizationId, (int) e.get("id"));
				auto_reg_client_name = (String) applicationInfo.get("name");
				auto_reg_client_id = (String) applicationInfo.get("clientId");
				auto_reg_client_secret = (String) applicationInfo.get("clientSecret");
				break;
			}
		}
*/
		
		/*
		 * Create the API in API Manager
		 */
		String apiMgmtAssetId = null;
		String apiMgmtAssetVersionId = null;
		String apiMgmtAssetName = null;
		
		LinkedHashMap<String, Object> apiAsset = null;
		ArrayList<LinkedHashMap<String, Object>> apiAssets = null;
		apiAssets = getAPIAssets(client, authorizationHdr, businessGroupId, apiName);

		apiAsset = findApiAsset(apiAssets, myOrganizationName, businessGroupName, apiName, apiVersion);
		apiMgmtAssetId = findApiId(apiAssets, myOrganizationName, businessGroupName, apiName);

		if (apiMgmtAssetId != null && apiAsset == null) {
			publishNewVersion(client, authorizationHdr, apiMgmtAssetId, apiVersion, myOrganizationName, myOrganizationId,
					businessGroupName, businessGroupId);
			apiAssets = getAPIAssets(client, authorizationHdr, businessGroupId, apiName);
			apiAsset = findApiAsset(apiAssets, myOrganizationName, businessGroupName, apiName, apiVersion);
		} else if (apiAsset == null) {
			publishApiAndVersion(client, authorizationHdr, apiName, apiVersion, myOrganizationName, myOrganizationId,
					businessGroupName, businessGroupId);
			apiAssets = getAPIAssets(client, authorizationHdr, businessGroupId, apiName);
			apiAsset = findApiAsset(apiAssets, myOrganizationName, businessGroupName, apiName, apiVersion);
		}
		apiMgmtAssetId = apiAsset.get("apiId").toString();
		apiMgmtAssetVersionId = apiAsset.get("id").toString();
		
		publishEndpoints(client, authorizationHdr, apiMgmtAssetId, apiMgmtAssetVersionId, myOrganizationName, myOrganizationId,
				businessGroupName, businessGroupId);
		
		StringBuilder sb = new StringBuilder();
		sb.append(apiName);
		if (makeApiNameBusinessGroupSensitive) {
			sb.append("_").append(businessGroupName);
		}
		sb.append("_");
		sb.append(apiVersion);
		apiMgmtAssetName = sb.toString();
		
		/*For consistency with other versions of ApiConfigTool*/
		String apiManagerAssetId = apiMgmtAssetId;
		String autoDiscoveryApiName = apiMgmtAssetName;
		String autoDiscoveryApiVersion = apiVersion;
		String autoDiscoveryApiId = null;

		/*
		 * Create the application information
		 */
/*
		String generated_client_name = null;
		String generated_client_id = null;
		String generated_client_secret = null;
		StringBuilder applicationName = new StringBuilder();
		applicationName.append(exchangeAssetName).append("_").append(environmentName);
		createApplication(client, authorizationHdr, myOrganizationId, applicationName.toString(), null);
		applications = getApplicationList(client, authorizationHdr, myOrganizationId);
		applicationInfo = null;
		for (LinkedHashMap<String, Object> e:applications) {
			if (e.get("name").equals(applicationName.toString())) {
				applicationInfo = getApplicationInformation(client, authorizationHdr, myOrganizationId, (int) e.get("id"));
				generated_client_name = (String) applicationInfo.get("name");
				generated_client_id = (String) applicationInfo.get("clientId");
				generated_client_secret = (String) applicationInfo.get("clientSecret");
				break;
			}
		}
*/
		
		/*
		 * Add API Policies
		 */
		addApiPolicies(client, authorizationHdr, businessGroupId, apiMgmtAssetId, apiMgmtAssetVersionId, policies);
		getApiPolicies(client, authorizationHdr, businessGroupId, apiMgmtAssetId, apiMgmtAssetVersionId);
		
		/*
		 * Add application contracts
		 */
		applications = getApplicationList(client, authorizationHdr, businessGroupId);
		createApplicationContracts(client, authorizationHdr, businessGroupId,
				businessGroupName, businessGroupId, Integer.parseInt(apiMgmtAssetVersionId), clients,
				applications);
		
		// save configuration
		ArrayList<Object> empty = new ArrayList<Object>();
		returnPayload.put("imports", empty.toArray());
		returnPayloadProperties.put("secure.properties",
				"generated_client_secret,cps_client_secret,auto_api_registration_client_secret");
		returnPayloadProperties.put("apiName", apiName);
		returnPayloadProperties.put("apiManagerAssetId", apiManagerAssetId);
		returnPayloadProperties.put("apiVersion", apiVersion);
		returnPayloadProperties.put("exchangeAssetName", apiMgmtAssetName);
		returnPayloadProperties.put("exchangeAssetId", apiMgmtAssetId);
		returnPayloadProperties.put("exchangeAssetVersion", apiMgmtAssetVersionId);
		returnPayloadProperties.put("exchangeAssetVersionGroup", (String) apiAsset.get("versionGroup"));
		returnPayloadProperties.put("exchangeAssetGroupId", (String) apiAsset.get("groupId"));
		returnPayloadProperties.put("exchangeAssetOrganizationId", (String) apiAsset.get("groupId"));
		returnPayloadProperties.put("auto-discovery-apiId", autoDiscoveryApiId);
		returnPayloadProperties.put("auto-discovery-apiName", autoDiscoveryApiName);
		returnPayloadProperties.put("auto-discovery-apiVersion", autoDiscoveryApiVersion);
		/*
		returnPayloadProperties.put("generated_client_name", generated_client_name);
		returnPayloadProperties.put("generated_client_id", generated_client_id);
		returnPayloadProperties.put("generated_client_secret", generated_client_secret);
		returnPayloadProperties.put("cps_client_name", cps_client_name);
		returnPayloadProperties.put("cps_client_id", cps_client_id);
		returnPayloadProperties.put("cps_client_secret", cps_client_secret);
		returnPayloadProperties.put("auto_api_registration_client_name", auto_reg_client_name);
		returnPayloadProperties.put("auto_api_registration_client_id", auto_reg_client_id);
		returnPayloadProperties.put("auto_api_registration_client_secret", auto_reg_client_secret);
*/
		returnPayload.put("properties", returnPayloadProperties);

		return returnPayload;
	}

	@SuppressWarnings("unchecked")
	private static String getAPToken(Client restClient, String user, String password) throws JsonProcessingException {
		String token = null;
		LinkedHashMap<String, Object> loginValues = new LinkedHashMap<String, Object>();
		loginValues.put("username", user);
		loginValues.put("password", password);
		String payload = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(loginValues);
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("accounts/login");

		Response response = target.request().accept(MediaType.APPLICATION_JSON)
				.post(Entity.entity(payload, MediaType.APPLICATION_JSON));

		int statuscode = 500;
		Map<String, Object> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 200) {
			result = response.readEntity(Map.class);
			token = (String) result.get("access_token");
		} else {
			System.err.println("Failed to login...check credentials");
			System.exit(statuscode);
		}

		return token;
	}

	@SuppressWarnings("unchecked")
	private static LinkedHashMap<String, Object> getMyInformation(Client restClient, String authorizationHdr)
			throws JsonProcessingException {
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("accounts/api/me");

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).get();

		int statuscode = 500;
		LinkedHashMap<String, Object> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 200) {
			result = response.readEntity(LinkedHashMap.class);
		} else {
			System.err.println("Failed to get login profile");
			System.exit(statuscode);
		}

//		 ObjectMapper mapperw = new ObjectMapper();
//		 System.err.println("myInformation: " +
//		 mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
		return result;
	}

	private static LinkedHashMap<String, Object> getBusinessGroupInformation(
			ArrayList<LinkedHashMap<String, Object>> memberOfOrganizations, String businessGroupName)
			throws JsonProcessingException {
		LinkedHashMap<String, Object> result = null;

		for (LinkedHashMap<String, Object> i : memberOfOrganizations) {
			if (i.get("name").equals(businessGroupName)) {
				result = i;
				break;
			}
		}

		if (result != null) {
			// ObjectMapper mapperw = new ObjectMapper();
			// System.err.println(
			// "businessGroupInformation: " +
			// mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
			return result;
		} else {
			System.err.println("Failed to find business Group information for " + businessGroupName);
			System.exit(404);
			return null;
		}

	}

	@SuppressWarnings("unchecked")
	private static LinkedHashMap<String, Object> getEnvironmentInformation(Client restClient, String authorizationHdr,
			String businessGroupId, String environmentName) throws JsonProcessingException {
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("accounts/api/organizations")
				.path(businessGroupId).path("environments");

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).get();

		int statuscode = 500;
		LinkedHashMap<String, Object> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 200) {
			result = response.readEntity(LinkedHashMap.class);
		} else {
			System.err.println("Failed to get environment information");
			System.exit(statuscode);
		}

		for (LinkedHashMap<String, Object> i : (ArrayList<LinkedHashMap<String, Object>>) result.get("data")) {
			if (i.get("name").equals(environmentName)) {
				result = i;
				break;
			}
		}

		if (result != null) {
//			 ObjectMapper mapperw = new ObjectMapper();
//			 System.err.println("environment: " +
//			 mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
			return result;
		} else {
			System.err.println("Failed to find environment information");
			System.exit(404);
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	private static ArrayList<LinkedHashMap<String, Object>> getApplicationList(Client restClient, String authorizationHdr,
			String organizationId) throws JsonProcessingException {
		
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
			.path(organizationId).path("applications").queryParam("limit", 250)
			.queryParam("offset", 0);

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).get();

		int statuscode = 500;
		ArrayList<LinkedHashMap<String, Object>> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 200) {
			LinkedHashMap<String, Object>tresult = (LinkedHashMap<String, Object>) response.readEntity(LinkedHashMap.class);
			result = (ArrayList<LinkedHashMap<String, Object>>) tresult.get("applications");
		} else {
			System.err.println("Failed to get application list (" + statuscode + ")");
			System.exit(statuscode);
		}

		if (result != null) {
//			ObjectMapper mapperw = new ObjectMapper();
//			System.err.println("applications: " + mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
			return result;
		} else {
			System.err.println("Failed to find list of applications");
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	private static LinkedHashMap<String, Object> getApplicationInformation(Client restClient, String authorizationHdr,
			String organizationId, int applicationId) throws JsonProcessingException {
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("exchange/api/v1/organizations")
				.path(organizationId).path("applications").path(Integer.toString(applicationId));

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).get();

		int statuscode = 500;
		LinkedHashMap<String,Object> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 200) {
			result = (LinkedHashMap<String, Object>) response.readEntity(LinkedHashMap.class);
		} else {
			System.err.println("Failed to get application information (" + statuscode + ")");
			System.exit(statuscode);
		}

		if (result != null) {
//			ObjectMapper mapperw = new ObjectMapper();
//			System.err.println("application: " + mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
			return result;
		} else {
			System.err.println("Failed to find application information");
			return null;
		}
	}

	private static void createApplication(Client restClient, String authorizationHdr,
			String organizationId, String applicationName, String description) throws JsonProcessingException {
		String desc = (description == null)
				? "Auto generated client credentials for this API instance to use calling other dependencies."
				: description;
		LinkedHashMap<String, Object> applicationValues = new LinkedHashMap<String, Object>();
		applicationValues.put("name", applicationName);
		applicationValues.put("description", desc);
		applicationValues.put("redirectUri", new ArrayList<String>());
		applicationValues.put("grantTypes", new ArrayList<String>());
		applicationValues.put("apiEndpoints", false);
		String payload = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(applicationValues);
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("exchange/api/v1/organizations")
				.path(organizationId).path("applications");

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).post(Entity.entity(payload, MediaType.APPLICATION_JSON));

		int statuscode = 500;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && (response.getStatus() == 201 || response.getStatus() == 409)) {
//			System.err.println(response.readEntity(String.class));
		} else {
			System.err.println("Failed to create application information (" + statuscode + ")");
			System.err.println(response.readEntity(String.class));
			System.exit(statuscode);
		}
	}

	private static void createApplicationContracts(Client restClient, String authorizationHdr, String organizationId,
			String businessGroupName, String businessGroupId,
			int apiVersionId, String contractsFileName,
			ArrayList<LinkedHashMap<String, Object>> applications) throws JsonProcessingException {

		ArrayList<LinkedHashMap<String, Object>> contracts;
		ObjectMapper mapper;
		TypeFactory factory;
		CollectionType type;

		factory = TypeFactory.defaultInstance();
		type = factory.constructCollectionType(ArrayList.class, LinkedHashMap.class);
		mapper = new ObjectMapper();

		InputStream is = null;
		File contractsFile = new File(contractsFileName);
		String contractsStr = null;
		try {
			if (contractsFile.exists()) {
				contractsStr = FileUtils.readFileToString(contractsFile, "UTF-8");
			} else {
				is = ApiConfigTool.class.getClassLoader().getResourceAsStream(contractsFileName);
				contractsStr = IOUtils.toString(is, "UTF-8");
			}
//			System.err.println(contractsStr);
			contracts = mapper.readValue(contractsStr, type);

			for (LinkedHashMap<String, Object> i : contracts) {
				int applicationId = 0;
				StringBuilder applicationName = new StringBuilder();
				applicationName.append(i.get("applicationName"));
//				System.err.println(applicationName.toString());
				for (LinkedHashMap<String, Object> e:applications) {
					if (e.get("name").equals(applicationName.toString())) {
						applicationId = (int) e.get("id");
						break;
					}
				}
				if (applicationId != 0) {
					createApplicationContract(restClient, authorizationHdr, organizationId, applicationId,
							businessGroupId, apiVersionId);
				} else {
					System.err.println("Could not find application in list: " + applicationName);
				}
			}

		} catch (Exception e) {
			System.err.println("Cannot use contracts file " + contractsFileName);
			e.printStackTrace(System.err);
		} finally {
			if (is != null) IOUtils.closeQuietly(is);
		}

	}

	private static void createApplicationContract(Client restClient, String authorizationHdr,
			String organizationId, int applicationId, String businessGroupId,
			int apiVersionId) throws JsonProcessingException {
		LinkedHashMap<String, Object> contractValues = new LinkedHashMap<String, Object>();
		contractValues.put("apiVersionId", apiVersionId);
		contractValues.put("applicationId", applicationId);
		contractValues.put("partyId", "");
		contractValues.put("partyName", "");
		String payload = new ObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(contractValues);

		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
				.path(organizationId).path("applications").path(Integer.toString(applicationId)).path("contracts");

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).post(Entity.entity(payload, MediaType.APPLICATION_JSON));

		int statuscode = 500;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && (response.getStatus() == 201 || response.getStatus() == 409)) {
//			System.err.println(response.readEntity(String.class));
		} else {
			System.err.println("Failed to create application contract (" + statuscode + ")");
			System.err.println(response.readEntity(String.class));
		}
	}

	@SuppressWarnings("unchecked")
	private static String findApiId(ArrayList<LinkedHashMap<String, Object>> assetList,
			String organizationName, String groupName, String apiName)
			throws JsonProcessingException {
		LinkedHashMap<String, Object> result = null;
		StringBuilder sb = new StringBuilder();
		sb.append(apiName);
		if (makeApiNameBusinessGroupSensitive) {
			sb.append("_").append(groupName);
		}
		String name = sb.toString();
		String apiId = null;

		for (LinkedHashMap<String, Object> i : assetList) {
			if (i.get("name").equals(name)) {
				apiId = i.get("id").toString();
				break;
			}
		}

		return apiId;
	}

	@SuppressWarnings("unchecked")
	private static LinkedHashMap<String, Object> findApiAsset(ArrayList<LinkedHashMap<String, Object>> assetList,
			String organizationName, String groupName, String apiName, String apiVersion)
			throws JsonProcessingException {
		LinkedHashMap<String, Object> result = null;
		StringBuilder sb = new StringBuilder();
		sb.append(apiName);
		if (makeApiNameBusinessGroupSensitive) {
			sb.append("_").append(groupName);
		}
		String name = sb.toString();

		for (LinkedHashMap<String, Object> i : assetList) {
			if (i.get("name").equals(name)) {
				ArrayList<LinkedHashMap<String, Object>> versions = (ArrayList<LinkedHashMap<String, Object>>) i
						.get("versions");
				boolean found = false;
				for (LinkedHashMap<String, Object> v : versions) {
					if (v.get("name").equals(apiVersion)) {
						result = v;
						found = true;
						break;
					}
				}
				if (found) {
					break;
				}
			}
		}

//		if (result != null) {
//			ObjectMapper mapperw = new ObjectMapper();
//			System.err.println(
//					"existing API asset: " + mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
//		}
		return result;
	}

	@SuppressWarnings("unchecked")
	private static ArrayList<LinkedHashMap<String, Object>> getAPIAssets(Client restClient,
			String authorizationHdr, String businessGroupId, String name) throws JsonProcessingException {
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
				.path(businessGroupId).path("apis").queryParam("limit", 250)
				.queryParam("offset", 0)
				.queryParam("query", name);

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).get();

		int statuscode = 500;
		LinkedHashMap<String, Object> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 200) {
			result = response.readEntity(LinkedHashMap.class);
		} else {
			System.err.println("Failed to get API Manager assets (" + statuscode + ")");
			return null;
		}

		if (result != null && result.get("apis") != null) {
//			ObjectMapper mapperw = new ObjectMapper();
//			System.err.println("assets: " + mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result.get("apis")));
			return (ArrayList<LinkedHashMap<String, Object>>) result.get("apis");
		} else {
			// System.err.println("Failed to find Exchange assets");
			return null;
		}
	}

	@SuppressWarnings("unchecked")
	private static void publishApiAndVersion(Client restClient, String authorizationHdr, String apiName,
			String apiVersion, String organizationName, String organizationId, String groupName, String groupId)
			throws JsonProcessingException {

		StringBuilder name = new StringBuilder();
		name.append(apiName);
		if (makeApiNameBusinessGroupSensitive) {
			name.append("_").append(groupName);
		}
		
		String addApi = null;
		LinkedHashMap<String,Object> apiAttributes = new LinkedHashMap<String,Object>();
		LinkedHashMap<String,Object> versionAttributes = new LinkedHashMap<String,Object>();
		apiAttributes.put("name", name.toString());
		apiAttributes.put("version", versionAttributes);
		versionAttributes.put("name", apiVersion);
		versionAttributes.put("description", "Auto generated by " + API_VERSION_HEADER_MSG);
		ObjectMapper mapperw = new ObjectMapper();
		addApi = mapperw.writeValueAsString(apiAttributes);

		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
				.path(groupId).path("apis");
		Response response = target.request().accept(MediaType.APPLICATION_JSON)
				.header("Authorization", authorizationHdr).post(Entity.entity(addApi, MediaType.APPLICATION_JSON));
		
		int statuscode = 500;
		LinkedHashMap<String, Object> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 201) {
			result = response.readEntity(LinkedHashMap.class);
		} else {
			System.err.println("Failed to post API to API Manager. (" + statuscode + ")");
			System.err.println(response.readEntity(String.class));

		}
		
		if (result != null) {
//			 System.err.println(
//			 "new API Manager asset: " +
//			 mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
		} else {
			System.err.println("Failed to publish API Manager asset");
			System.exit(statuscode);
		}
	}

	@SuppressWarnings("unchecked")
	private static void publishNewVersion(Client restClient, String authorizationHdr, String apiMgmtAssetId,
			String apiVersion, String organizationName, String organizationId, String groupName, String groupId)
			throws JsonProcessingException {
		
		String addApi = null;
		LinkedHashMap<String,Object> versionAttributes = new LinkedHashMap<String,Object>();
		versionAttributes.put("name", apiVersion);
		versionAttributes.put("description", "Auto generated by " + API_VERSION_HEADER_MSG);
		ObjectMapper mapperw = new ObjectMapper();
		addApi = mapperw.writeValueAsString(versionAttributes);

		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
				.path(groupId).path("apis").path(apiMgmtAssetId).path("versions");
		Response response = target.request().accept(MediaType.APPLICATION_JSON)
				.header("Authorization", authorizationHdr).post(Entity.entity(addApi, MediaType.APPLICATION_JSON));
		
		int statuscode = 500;
		LinkedHashMap<String, Object> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 201) {
			result = response.readEntity(LinkedHashMap.class);
		} else {
			System.err.println("Failed to post API to API Manager. (" + statuscode + ")");
			System.err.println(response.readEntity(String.class));

		}
		
		if (result != null) {
//			 System.err.println(
//			 "new API Manager asset: " +
//			 mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
		} else {
			System.err.println("Failed to publish API Manager asset");
			System.exit(statuscode);
		}
	}

	@SuppressWarnings("unchecked")
	private static void publishEndpoints(Client restClient, String authorizationHdr, String apiMgmtAssetId,
			String apiVersionId, String organizationName, String organizationId, String groupName, String groupId)
			throws JsonProcessingException {
		
		WebTarget target = null;
		Response response = null;
		
		target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
				.path(groupId).path("apis").path(apiMgmtAssetId).path("versions").path(apiVersionId).path("portal");
		response = target.request().accept(MediaType.APPLICATION_JSON)
				.header("Authorization", authorizationHdr).post(Entity.entity("{}", MediaType.APPLICATION_JSON));

		LinkedHashMap<String,Object> endpointAttributes = new LinkedHashMap<String,Object>();
		endpointAttributes.put("type", "http");
		endpointAttributes.put("uri", "http://anyhost.com/abc");
		endpointAttributes.put("isCloudHub", false);
		endpointAttributes.put("proxyUri", "http://0.0.0.0:8081/");
		endpointAttributes.put("referencesUserDomain", false);
		endpointAttributes.put("responseTimeout", null);
		endpointAttributes.put("apiVersionId", apiVersionId);
		target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
				.path(groupId).path("apis").path(apiMgmtAssetId).path("versions").path(apiVersionId).path("endpoint");
		response = target.request().accept(MediaType.APPLICATION_JSON)
				.header("Authorization", authorizationHdr).post(Entity.entity(endpointAttributes, MediaType.APPLICATION_JSON));
	}

	@SuppressWarnings("unchecked")
	private static ArrayList<LinkedHashMap<String, Object>> getApiPolicies(Client restClient, String authorizationHdr,
			String businessGroupId, String apiId, String versionId) throws JsonProcessingException {
		WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
				.path(businessGroupId).path("apis").path(apiId).path("versions").path(versionId)
				.path("policies");

		Response response = target.request().header("Authorization", authorizationHdr)
				.accept(MediaType.APPLICATION_JSON).get();

		int statuscode = 500;
		ArrayList<LinkedHashMap<String, Object>> result = null;
		if (response != null) {
			statuscode = response.getStatus();
		}
		if (response != null && response.getStatus() == 200) {
			result = (ArrayList<LinkedHashMap<String, Object>>) response.readEntity(ArrayList.class);
		} else {
			System.err.println("Failed to get API policies (" + statuscode + ")");
			return null;
		}

		if (result != null) {
//			ObjectMapper mapperw = new ObjectMapper();
//			System.err.println("api policies: " + mapperw.writerWithDefaultPrettyPrinter().writeValueAsString(result));
			return result;
		} else {
			System.err.println("Failed to find API policies");
			return null;
		}
	}

	private static void addApiPolicies(Client restClient, String authorizationHdr, String businessGroupId,
			String apiId, String versionId, String apiPolicies) {

		ArrayList<LinkedHashMap<String, Object>> policies;
		ObjectMapper mapper;
		TypeFactory factory;
		CollectionType type;

		factory = TypeFactory.defaultInstance();
		type = factory.constructCollectionType(ArrayList.class, LinkedHashMap.class);
		mapper = new ObjectMapper();

		InputStream is = null;
		File policyFile = new File(apiPolicies);
		String policiesStr = null;
		try {
			if (policyFile.exists()) {
				policiesStr = FileUtils.readFileToString(policyFile, "UTF-8");
			} else {
				is = ApiConfigTool.class.getClassLoader().getResourceAsStream(apiPolicies);
				policiesStr = IOUtils.toString(is, "UTF-8");
			}
//			System.err.println(policiesStr);
			policies = mapper.readValue(policiesStr, type);

			for (LinkedHashMap<String, Object> i : policies) {
				addApiPolicy(restClient, authorizationHdr, businessGroupId, apiId, versionId, i);
			}

		} catch (Exception e) {
			System.err.println("Cannot use policies from file " + apiPolicies);
			e.printStackTrace(System.err);
			System.exit(1);
		} finally {
			if (is != null) IOUtils.closeQuietly(is);
		}

	}

	private static void addApiPolicy(Client restClient, String authorizationHdr, String businessGroupId,
			String apiId, String versionId, LinkedHashMap<String, Object> apiPolicy)
			throws JsonProcessingException {

		String policyStr = null;
		try {
			ObjectMapper mapperw = new ObjectMapper();
			policyStr = mapperw.writeValueAsString(apiPolicy);
//			System.err.println("Setting policy " + policyStr);
//			/apiplatform/repository/v2/organizations/2d994582-1663-4153-86f9-15bd7ec38cb8/apis/5/versions/6/policies
			WebTarget target = restClient.target(HTTPS_ANYPOINT_MULESOFT_COM).path("apiplatform/repository/v2/organizations")
					.path(businessGroupId).path("apis").path(apiId).path("versions").path(versionId)
					.path("policies");

			Response response = target.request().accept(MediaType.APPLICATION_JSON)
					.header("Authorization", authorizationHdr)
					.post(Entity.entity(policyStr, MediaType.APPLICATION_JSON));

			int statuscode = 500;
			if (response != null) {
				statuscode = response.getStatus();
			}
			if (response != null && (response.getStatus() == 201 || response.getStatus() == 409)) {
//				System.err.println(response.readEntity(String.class));
			} else {
				System.err.println("Failed to apply policy " + policyStr + ". (" + statuscode + ")");
				System.err.println(response.readEntity(String.class));
			}
		} catch (Exception e) {
			System.err.println("Cannot set policy:\n " + policyStr);
			e.printStackTrace(System.err);
		}
	}
}

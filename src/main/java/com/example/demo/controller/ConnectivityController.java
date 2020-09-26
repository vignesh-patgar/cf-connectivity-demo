package com.example.demo.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Base64;

/*import org.cloudfoundry.identity.client.UaaContext;
import org.cloudfoundry.identity.client.UaaContextFactory;
import org.cloudfoundry.identity.client.token.GrantType;
import org.cloudfoundry.identity.client.token.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;*/
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;


@RestController
public class ConnectivityController {
	private static final Logger LOGGER = LoggerFactory.getLogger(ConnectivityController.class);
	String responseString = null;
	@RequestMapping("/connect")
	public String getConnection() {
		JSONObject jsonObj = null;
		JSONObject jsonResponse = null;
		HttpURLConnection urlConnection = null;
		try {
			jsonObj = new JSONObject(System.getenv("VCAP_SERVICES"));

			JSONArray jsonArr;

			jsonArr = jsonObj.getJSONArray("connectivity");

			JSONObject connectivityCredentials = jsonArr.getJSONObject(0).getJSONObject("credentials");
			
			JSONObject jsonObjXsuaa = new JSONObject(System.getenv("VCAP_SERVICES"));
			JSONArray jsonArrXsuaa = jsonObjXsuaa.getJSONArray("xsuaa");
			JSONObject xsuaaCredentials = jsonArrXsuaa.getJSONObject(0).getJSONObject("credentials");
			
			String connProxyHost = connectivityCredentials.getString("onpremise_proxy_host");
			int connProxyPort = Integer.parseInt(connectivityCredentials.getString("onpremise_proxy_http_port"));
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(connProxyHost, connProxyPort));
			URL url = new URL("http://jiracf:443/rest/api/latest/project/S4TRBKBLR5V1");
			LOGGER.info("Connecting to backend system " + connectivityCredentials);
			urlConnection = (HttpURLConnection) url.openConnection(proxy);
			
			//Authentication
			// get value of "clientid" and "clientsecret" from the environment variables
			String clientid = connectivityCredentials.getString("clientid");
			String clientsecret = connectivityCredentials.getString("clientsecret");
			//UaaContextFactory factory = UaaContextFactory.factory(xsuaaUrl).authorizePath("/oauth/authorize").tokenPath("/oauth/token");
			// get the URL to xsuaa from the environment variables
			URI xsuaaUrl = new URI(xsuaaCredentials.getString("url"));
			LOGGER.info("Got URL xsuaaURL " + xsuaaUrl);
			 
			// make request to UAA to retrieve access token
/*			UaaContextFactory factory = UaaContextFactory.factory(xsuaaUrl).authorizePath("/oauth/authorize").tokenPath("/oauth/token");
			TokenRequest tokenRequest = factory.tokenRequest();
			tokenRequest.setGrantType(GrantType.CLIENT_CREDENTIALS);
			tokenRequest.setClientId(clientid);
			tokenRequest.setClientSecret(clientsecret);
			UaaContext xsuaaContext = factory.authenticate(tokenRequest);
			CompositeAccessToken accessToken = xsuaaContext.getToken();*/
			 
			 
			// set access token as Proxy-Authorization header in the URL connection
			//urlConnection.setRequestProperty("Proxy-Authorization", "Bearer " + accessToken);
			//Different way
			XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(
					new DefaultOAuth2TokenService(),
					new XsuaaDefaultEndpoints(xsuaaUrl), new ClientCredentials(clientid, clientsecret));
			OAuth2TokenResponse tokenResponse = tokenFlows.clientCredentialsTokenFlow().execute();
			urlConnection.setRequestProperty("Proxy-Authorization", "Bearer " + tokenResponse.getAccessToken());
			LOGGER.info("token flow successs" + tokenResponse.getAccessToken());	
			
			String userName = "";
			String password = "";
			String userpass = userName + ":" + password;
			String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userpass.getBytes()));
			urlConnection.setRequestProperty ("Authorization", basicAuth);
			
			//Connect to service
			InputStream in = urlConnection.getInputStream();
			LOGGER.info("Data is read");
			InputStreamReader isr = new InputStreamReader(in);
			BufferedReader br = new BufferedReader(isr);

			String inputLine;
			StringBuffer responseStringBuffer = new StringBuffer();
			while ((inputLine = br.readLine()) != null) {
				responseStringBuffer.append(inputLine);
			}
			br.close();

			responseString = responseStringBuffer.toString();
			LOGGER.info(responseString);
			jsonResponse = new JSONObject(responseString);
		} catch (JSONException | IOException | URISyntaxException  e) {
			LOGGER.error("error", e);
			e.printStackTrace();
		}
		finally {
			if(urlConnection != null) {
			urlConnection.disconnect();
			}
		}
		return responseString;
	}
}
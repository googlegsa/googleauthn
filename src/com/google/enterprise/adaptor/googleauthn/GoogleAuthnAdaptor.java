// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.googleauthn;

import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.AuthnAdaptor;
import com.google.enterprise.adaptor.AuthnIdentity;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.HttpExchanges;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.Session;

import com.google.gdata.client.authn.oauth.GoogleOAuthParameters;
import com.google.gdata.client.authn.oauth.OAuthException;
import com.google.gdata.client.authn.oauth.OAuthHmacSha1Signer;
import com.google.gdata.client.authn.oauth.OAuthParameters;
import com.google.gdata.client.authn.oauth.OAuthSigner;
import com.google.gdata.data.Link;
import com.google.gdata.util.AuthenticationException;
import com.google.gdata.util.ServiceException;
import com.google.gdata.client.appsforyourdomain.AppsGroupsService;
import com.google.gdata.data.appsforyourdomain.generic.GenericEntry;
import com.google.gdata.data.appsforyourdomain.generic.GenericFeed;

import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;

import java.io.IOException;
import java.net.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Adaptor that authenticates users with Google. */
public class GoogleAuthnAdaptor extends AbstractAdaptor
    implements AuthnAdaptor {
  private static final String PROGRAM_NAME = "GoogleAuthnAdaptor/v0.1";
  private static final String SESSION_DATA = "authndata";

  private static final Logger log
      = Logger.getLogger(GoogleAuthnAdaptor.class.getName());

  private AdaptorContext context;
  private HttpContext responseContext;
  private List<DiscoveryInformation> discoveries;
  private String consumerKey;
  private String consumerSecret;
  private String domain;

  @Override
  public void initConfig(Config config) {
    config.addKey("google-authn.consumerKey", null);
    config.addKey("google-authn.consumerSecret", null);
    config.addKey("google-authn.domain", null);
  }

  @Override
  public void init(AdaptorContext context) throws IOException {
    this.context = context;
    Config config = context.getConfig();
    consumerKey = config.getValue("google-authn.consumerKey");
    consumerSecret = context.getSensitiveValueDecoder().decodeValue(
        config.getValue("google-authn.consumerSecret"));
    domain = config.getValue("google-authn.domain");

    log.log(Level.CONFIG, "google-authn.consumerKey: {0}", consumerKey);
    log.log(Level.CONFIG, "google-authn.domain: {0}", domain);

    try {
      @SuppressWarnings("unchecked")
      List<DiscoveryInformation> discoveries = new ConsumerManager()
          .discover("https://www.google.com/accounts/o8/id");
      this.discoveries = discoveries;
    } catch (DiscoveryException ex) {
      throw new IOException(ex);
    }

    if (discoveries.isEmpty()) {
      throw new RuntimeException("Could not discover openid endpoint");
    }

    responseContext = context.createHttpContext(
        "/google-response", new ResponseHandler());
  }

  @Override
  public void destroy() {
    discoveries = null;
    responseContext.getServer().removeContext(responseContext);
    responseContext = null;
  }

  @Override
  public void authenticateUser(HttpExchange ex, Callback callback)
      throws IOException {
    ConsumerManager manager = new ConsumerManager();
    DiscoveryInformation discovered = manager.associate(discoveries);
    URI requestUri = HttpExchanges.getRequestUri(ex);
    URI returnUri = requestUri.resolve(responseContext.getPath());
    AuthRequest request;
    try {
      request = manager.authenticate(discovered, returnUri.toASCIIString());
    } catch (OpenIDException e) {
      log.log(Level.WARNING, "Authn failed: OpenIDException", e);
      callback.userAuthenticated(ex, null);
      return;
    }
    FetchRequest fetch = FetchRequest.createFetchRequest();
    try {
      fetch.addAttribute("email", "http://axschema.org/contact/email", true);
      request.addExtension(fetch);
    } catch (MessageException e) {
      log.log(Level.WARNING, "Authn failed: MessageException", e);
      callback.userAuthenticated(ex, null);
      return;
    }
    Session session = context.getUserSession(ex, true);
    session.setAttribute(SESSION_DATA,
        new SessionData(manager, discovered, callback));
    HttpExchanges.sendRedirect(ex, URI.create(request.getDestinationUrl(true)));
  }

  @Override
  public void getDocIds(DocIdPusher pusher) {}

  @Override
  public void getDocContent(Request request, Response response)
      throws IOException {
    response.respondNotFound();
  }

  public static void main(String[] args) throws Exception {
    AbstractAdaptor.main(new GoogleAuthnAdaptor(), args);
  }

  private static Map<String, String[]> convertParameterListsToArrays(
      Map<String, List<String>> params) {
    Map<String, String[]> newMap = new HashMap<String, String[]>();
    String[] zeroArray = new String[0];
    for (Map.Entry<String, List<String>> me : params.entrySet()) {
      newMap.put(me.getKey(), me.getValue().toArray(zeroArray));
    }
    return newMap;
  }

  private List<String> getAllGroups(String username) throws IOException {
    // Username known to be valid and trusted.
    String userDomain = username.split("@", 2)[1];
    AppsGroupsService groupService;
    try {
      groupService = new AppsGroupsService(userDomain, PROGRAM_NAME);
    } catch (AuthenticationException ex) {
      throw new IOException("Failed to create groups service", ex);
    }
    GoogleOAuthParameters oauthParameters = getOAuthParameters();
    try {
      groupService.setOAuthCredentials(oauthParameters, getOAuthSigner());
    } catch (OAuthException e) {
      throw new IOException("Failed to set provisioning credentials", e);
    }
    try {
      log.log(Level.FINE, "Getting group entries for {0}", username);
      ArrayList<String> groups = new ArrayList<String>();
      GenericFeed groupsFeed = groupService.retrieveGroups(username, false);
      while (groupsFeed != null) {
        for (GenericEntry entry : groupsFeed.getEntries()) {
          // Use groupName instead of groupId because groupName uses the group's
          // canonical casing.
          groups.add(entry.getProperty("groupName") + "@" + domain);
        }
        Link nextPage = groupsFeed.getNextLink();
        if (nextPage == null) {
          groupsFeed = null;
        } else {
          groupsFeed = groupService.getFeed(
              new URL(nextPage.getHref()), GenericFeed.class);
        }
      }
      log.log(Level.FINE, "group count: {0}", groups.size());
      log.log(Level.FINER, "all groups: {0}", groups);
      return groups;
    } catch (ServiceException se) {
      throw new IOException("failed to get groups", se);
    }
  }

  private GoogleOAuthParameters getOAuthParameters() {
    GoogleOAuthParameters oauthParameters = new GoogleOAuthParameters();
    oauthParameters.setOAuthConsumerKey(consumerKey);
    oauthParameters.setOAuthConsumerSecret(consumerSecret);
    oauthParameters.setOAuthType(OAuthParameters.OAuthType.TWO_LEGGED_OAUTH);
    return oauthParameters;
  }

  private static OAuthSigner getOAuthSigner() {
    return new OAuthHmacSha1Signer();
  }

  private static class SessionData {
    private final ConsumerManager manager;
    private final DiscoveryInformation discovered;
    private final Callback callback;

    public SessionData(ConsumerManager manager, DiscoveryInformation discovered,
        Callback callback) {
      this.manager = manager;
      this.discovered = discovered;
      this.callback = callback;
    }
  }

  private class ResponseHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange ex) throws IOException {
      Session session = context.getUserSession(ex, false);
      if (session == null) {
        log.log(Level.WARNING, "Authn failed: Could not find user's session");
        // TODO(ejona): Translate.
        HttpExchanges.respond(ex, HttpURLConnection.HTTP_INTERNAL_ERROR,
            "text/plain",
            "Could not find user's session".getBytes(Charset.forName("UTF-8")));
        return;
      }
      SessionData sessionData
          = (SessionData) session.removeAttribute(SESSION_DATA);
      if (sessionData == null) {
        log.log(Level.WARNING, "Authn failed: Could not find session data");
        // TODO(ejona): Translate.
        HttpExchanges.respond(ex, HttpURLConnection.HTTP_INTERNAL_ERROR,
            "text/plain",
            "Could not find session data".getBytes(Charset.forName("UTF-8")));
        return;
      }
      ConsumerManager manager = sessionData.manager;
      DiscoveryInformation discovered = sessionData.discovered;
      Callback callback = sessionData.callback;
      URI requestUri = HttpExchanges.getRequestUri(ex);
      @SuppressWarnings("unchecked")
      Map<String, List<String>> params
          = manager.extractQueryParams(requestUri.toURL());
      ParameterList openidResp = new ParameterList(
          convertParameterListsToArrays(params));
      // TODO(ejona): compute requestUri directly from the exchange
      VerificationResult verification;
      try {
        verification = manager.verify(
            requestUri.toASCIIString(), openidResp, discovered);
      } catch (OpenIDException e) {
        log.log(Level.WARNING, "Authn failed: OpenIDException", e);
        callback.userAuthenticated(ex, null);
        return;
      }
      if (verification.getVerifiedId() == null) {
        if (Message.OPENID2_NS.equals(verification.getAuthResponse()
              .getParameterValue("openid.ns"))
            && Message.MODE_CANCEL.equals(verification.getAuthResponse()
              .getParameterValue("openid.mode"))) {
          log.log(Level.WARNING, "Authn failed: user canceled");
        } else {
          log.log(Level.WARNING, "Authn failed: verification failed");
        }
        callback.userAuthenticated(ex, null);
        return;
      }
      Message response = verification.getAuthResponse();
      FetchResponse ax;
      try {
        ax = (FetchResponse) response.getExtension(AxMessage.OPENID_NS_AX);
      } catch (MessageException e) {
        log.log(Level.WARNING, "Authn failed: MessageException", e);
        callback.userAuthenticated(ex, null);
        return;
      }
      if (ax == null) {
        log.log(Level.WARNING, "Authn failed: No ax extension");
        callback.userAuthenticated(ex, null);
        return;
      }
      final String email = ax.getAttributeValue("email");
      if (email == null) {
        log.log(Level.WARNING, "Authn failed: No email attribute");
        callback.userAuthenticated(ex, null);
        return;
      }
      log.log(Level.FINE, "User {0} authenticated", email);
      String[] parts = email.split("@", 2);
      if (parts.length != 2) {
        log.log(Level.WARNING,
            "Authn failed: Could not determine user's domain: {0}", email);
        callback.userAuthenticated(ex, null);
        return;
      }
      if (!domain.equals(parts[1])) {
        log.log(Level.WARNING,
            "Authn failed: User {0} has domain {1} which is not the expected "
            + "domain {2}", new Object[] {email, parts[1], domain});
        callback.userAuthenticated(ex, null);
        return;
      }
      final Set<String> groups;
      try {
        groups = Collections.unmodifiableSet(
            new HashSet<String>(getAllGroups(email)));
      } catch (IOException e) {
        log.log(Level.WARNING, "Authn failed: Error getting groups", e);
        callback.userAuthenticated(ex, null);
        return;
      }
      AuthnIdentity identity = new AuthnIdentity() {
        @Override
        public String getUsername() {
          return email;
        }

        @Override
        public String getPassword() {
          return null;
        }

        @Override
        public Set<String> getGroups() {
          return groups;
        }
      };
      callback.userAuthenticated(ex, identity);
    }
  }
}

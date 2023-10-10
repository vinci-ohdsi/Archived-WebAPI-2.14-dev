package org.ohdsi.webapi.shiro.filters;

import static org.ohdsi.webapi.shiro.management.AtlasSecurity.AUTH_CLIENT_ATTRIBUTE;
import static org.ohdsi.webapi.shiro.management.AtlasSecurity.PERMISSIONS_ATTRIBUTE;
import static org.ohdsi.webapi.shiro.management.AtlasSecurity.TOKEN_ATTRIBUTE;

import io.buji.pac4j.subject.Pac4jPrincipal;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.UriBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.util.WebUtils;
import org.ohdsi.webapi.Constants;
import org.ohdsi.webapi.shiro.Entities.UserPrincipal;
import org.ohdsi.webapi.shiro.PermissionManager;
import org.ohdsi.webapi.shiro.TokenManager;
import org.ohdsi.webapi.util.UserUtils;
import org.pac4j.core.profile.CommonProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author gennadiy.anisimov
 */
public class UpdateAccessTokenFilter extends AdviceFilter {
  private final Logger logger = LoggerFactory.getLogger(UpdateAccessTokenFilter.class);

  private final PermissionManager authorizer;
  private final int tokenExpirationIntervalInSeconds;
  private final Set<String> defaultRoles;
  private final String onFailRedirectUrl;
  private final String authorizationMode;

  public UpdateAccessTokenFilter(
          PermissionManager authorizer,
          Set<String> defaultRoles,
          int tokenExpirationIntervalInSeconds,
          String onFailRedirectUrl,
          String authorizationMode) {
    this.authorizer = authorizer;
    this.tokenExpirationIntervalInSeconds = tokenExpirationIntervalInSeconds;
    this.defaultRoles = defaultRoles;
    this.onFailRedirectUrl = onFailRedirectUrl;
    this.authorizationMode = authorizationMode;
    logger.debug("AUTHORIZATION_MODE in UpdateAccessTokenFilter constructor == '{}'", this.authorizationMode);
  }
  
  @Override
  protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
    if (!SecurityUtils.getSubject().isAuthenticated()) {
      WebUtils.toHttp(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      return false;
    }

    String login;
    String name = null;
    String jwt = null;
    final PrincipalCollection principals = SecurityUtils.getSubject().getPrincipals();
    Object principal = principals.getPrimaryPrincipal();  
    
    if (principal instanceof Pac4jPrincipal) {

      login = ((Pac4jPrincipal)principal).getProfile().getEmail();
      name = ((Pac4jPrincipal)principal).getProfile().getDisplayName();

      // Is the login null or empty?
      logger.debug("DEBUG: Principal login (email) after entry and test 'principal instanceof Pac4jPrincipal': {}", login);
      logger.debug("DEBUG: Principal name after entry and test 'principal instanceof Pac4jPrincipal': {}", name);
      
      /**
      * for CAS login
      */
      ShiroHttpServletRequest requestShiro = (ShiroHttpServletRequest) request;
      HttpSession shiroSession = requestShiro.getSession();
      if (login == null && shiroSession.getAttribute(CasHandleFilter.CONST_CAS_AUTHN) != null
              && ((String) shiroSession.getAttribute(CasHandleFilter.CONST_CAS_AUTHN)).equalsIgnoreCase("true")) {
              login = ((Pac4jPrincipal) principal).getProfile().getId();
      }

      logger.debug("DEBUG: Principal login (email) after requestShiro initialization: {}", login);
      logger.debug("DEBUG: Principal name after requestShiro initialization: {}", name);
    
      if (login == null) {
        // user doesn't provide email - send empty token
        request.setAttribute(TOKEN_ATTRIBUTE, "");
        // stop session to make logout of OAuth users possible
        Session session = SecurityUtils.getSubject().getSession(false);
        if (session != null) {
          session.stop();
        }

        HttpServletResponse httpResponse = WebUtils.toHttp(response);

        URI oauthFailURI = getOAuthFailUri();
        httpResponse.sendRedirect(oauthFailURI.toString());
        return false;
      }

      CommonProfile profile = (((Pac4jPrincipal) principal).getProfile());
      if (Objects.nonNull(profile)) {
	  String clientName = profile.getClientName();
	  request.setAttribute(AUTH_CLIENT_ATTRIBUTE, clientName);
      }
    } else if (principal instanceof Principal) {
      login = ((Principal) principal).getName();
      logger.debug("DEBUG: Principal name after second test 'principal instanceof Principal': {}", name);
    } else if (principal instanceof UserPrincipal){
      login = ((UserPrincipal) principal).getUsername();
      name = ((UserPrincipal) principal).getName();
      logger.debug("DEBUG: Principal login after test 'principal instanceof UserPrincipal': {}", login);
      logger.debug("DEBUG: Principal name after test 'principal instanceof UserPrincipal': {}", name);
    } else if (principal instanceof String) {
      login = (String)principal;
      logger.debug("DEBUG: Principal login after test 'principal instanceof String': {}", login);
    } else {
      throw new Exception("Unknown type of principal");
    }

    login = UserUtils.toLowerCase(login);
    logger.debug("DEBUG: Principal login after 'UserUtils.toLowerCase(login)': {}", login);
    logger.debug("DEBUG: Principal name after 'UserUtils.toLowerCase(name)': {}", name);
  
    // stop session to make logout of OAuth users possible
    Session session = SecurityUtils.getSubject().getSession(false);
    if (session != null) {
      session.stop();
    }

    if (jwt == null) { // dead check...jwt is always null...
      if (name == null) {
        name = login;
      }
      try {
        logger.debug("AUTHORIZATION_MODE in UpdateAccessTokenFilter == '{}'", this.authorizationMode);
        boolean resetRoles = false;
        Set<String> newUserRoles = new HashSet<String>();
        if (this.authorizationMode.equals("teamproject")) {
          // in case of "teamproject" mode, we want all roles to be reset always, and
          // set to only the one requested/found in the request parameters (following lines below):
          resetRoles = true;
          // check if a teamproject parameter is found in the request:
          String teamProjectRole = extractTeamProjectFromRequestParameters(request);
          // if found, add teamproject as a role in the newUserRoles list:
          if (teamProjectRole != null) {
            newUserRoles.add(teamProjectRole);
            // double check with Arborist if this role has really been granted to the user....
            // TODO
          }
        }
        this.authorizer.registerUser(login, name, defaultRoles, newUserRoles, resetRoles);
        
      } catch (Exception e) {
        WebUtils.toHttp(response).setHeader("x-auth-error", e.getMessage());
        throw new Exception(e);
      }

      String sessionId = (String) request.getAttribute(Constants.SESSION_ID);
      if (sessionId == null) {
        final String token = TokenManager.extractToken(request);
	logger.debug("DEBUG: token after TokenManager.extractToken(request): {}", token);
        if (token != null) {
          sessionId = (String) TokenManager.getBody(token).get(Constants.SESSION_ID);
        }
      }
      logger.debug("DEBUG: Session ID (if null, this means the token might be null): {}", sessionId);

      Date expiration = this.getExpirationDate(this.tokenExpirationIntervalInSeconds);
      jwt = TokenManager.createJsonWebToken(login, sessionId, expiration);

      if (jwt != null)
	  logger.debug("DEBUG: JWT is not null");

      if (expiration != null){
	  DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
	  logger.debug("DEBUG: expiration (based on {} seconds) : {}", this.tokenExpirationIntervalInSeconds, df.format(expiration));
      }
    }

    request.setAttribute(TOKEN_ATTRIBUTE, jwt);
    Collection<String> permissions = this.authorizer.getAuthorizationInfo(login).getStringPermissions();
    request.setAttribute(PERMISSIONS_ATTRIBUTE, StringUtils.join(permissions, "|"));
    return true;
  }

  private URI getOAuthFailUri() throws URISyntaxException {
    return getFailUri("oauth_error_email");
  }

  private URI getFailUri(String failFragment) throws URISyntaxException {

    URI oauthFailURI = new URI(onFailRedirectUrl);
    String fragment = oauthFailURI.getFragment();
    StringBuilder sbFragment = new StringBuilder();
    if(fragment == null) {
      sbFragment.append(failFragment).append("/");
    } else if(fragment.endsWith("/")){
      sbFragment.append(fragment).append(failFragment).append("/");
    } else {
      sbFragment.append(fragment).append("/").append(failFragment).append("/");
    }
    return UriBuilder.fromUri(oauthFailURI).fragment(sbFragment.toString()).build();
  }

  private Date getExpirationDate(final int expirationIntervalInSeconds) {
    Calendar calendar = Calendar.getInstance();
    calendar.add(Calendar.SECOND, expirationIntervalInSeconds);
    return calendar.getTime();
  }

  private String extractTeamProjectFromRequestParameters(ServletRequest request) {
    // Get the url
    HttpServletRequest httpRequest = (HttpServletRequest) request;
    String url = httpRequest.getRequestURL().toString();

    // try to find it in the redirectUrl parameter:
    logger.debug("Looking for redirectUrl in request: {}....", url);
    String[] redirectUrlParams = getParameterValues(request, "redirectUrl");
    if (redirectUrlParams != null) {
      logger.debug("Parameter redirectUrl found. Checking if it contains teamproject....");
      // teamProject will be in first one in this case...as only parameter:
      String firstParameter = redirectUrlParams[0].toLowerCase();
      if (firstParameter.contains("teamproject=")) {
        String teamProject = firstParameter.split("teamproject=")[1];
        logger.debug("Found teamproject: {}", teamProject);
        return teamProject;
      }
    }

    // try to find "teamproject" param in url itself (there will be no redirectUrl if user session is still valid):
    logger.debug("Fallback1: Looking for teamproject in request: {}....", url);
    String[] teamProjectParams = getParameterValues(request, "teamproject");
    if (teamProjectParams != null) {
      logger.debug("Parameter teamproject found. Parsing....");
      String teamProject = teamProjectParams[0].toLowerCase();
      logger.debug("Found teamproject: {}", teamProject);
      return teamProject;
    }

    logger.debug("Fallback2: Looking for teamproject in Action-Location header of request: {}....", url);
    String actionLocationUrl = httpRequest.getHeader("Action-Location");
    if (actionLocationUrl != null && actionLocationUrl.contains("teamproject=")) {
      String teamProject = actionLocationUrl.split("teamproject=")[1];
      logger.debug("Found teamproject: {}", teamProject);
      return teamProject;
    }

    logger.debug("Found NO teamproject.");
    return null;
  }

  private String[] getParameterValues(ServletRequest request, String parameterName) {
    // Get the parameters
    logger.debug("Looking for parameter with name: {} ...", parameterName);
    Enumeration<String> paramNames = request.getParameterNames();
    while(paramNames.hasMoreElements()) {
        String paramName = paramNames.nextElement();
        logger.debug("Parameter name: {}", paramName);
        if (paramName.equals(parameterName)) {
          String[] paramValues = request.getParameterValues(paramName);
          return paramValues;
        }
    }
    logger.debug("Found NO parameter with name: {}", parameterName);
    return null;
  }
}
